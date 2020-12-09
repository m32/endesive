#!/usr/bin/env vpython3
import sys
import time
import random
import io
import struct
import datetime
import hashlib
import codecs
import struct
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import signer
from endesive.pdf.PyPDF2 import pdf, generic as po


def EncodedString(s):
    return po.createStringObject(codecs.BOM_UTF16_BE + s.encode("utf-16be"))


class UnencryptedBytes(po.utils.bytes_type, po.PdfObject):
    original_bytes = property(lambda self: self)

    def writeToStream(self, stream, encryption_key):
        stream.write(b"<")
        stream.write(self)
        stream.write(b">")


class WNumberObject(po.NumberObject):
    Format = b"%08d"

    def writeToStream(self, stream, encryption_key):
        stream.write(self.Format % self)


class SignedData(pdf.PdfFileWriter):
    def encrypt(self, prev, password, rc):
        encrypt = prev.trailer["/Encrypt"].getObject()
        if encrypt["/V"] == 2:
            rev = 3
            keylen = int(128 / 8)
        else:
            rev = 2
            keylen = int(40 / 8)
        P = encrypt["/P"]
        O = encrypt["/O"]
        ID_1 = prev.trailer["/ID"][0]
        if rev == 2:
            U, key = pdf._alg34(password, O, P, ID_1)
        else:
            assert rev == 3
            U, key = pdf._alg35(password, rev, keylen, O, P, ID_1, False)
        self._encrypt_key = key

    def write(self, stream, prev, startdata):
        stream.write(pdf.b_("\r\n"))
        positions = {}
        for i in range(len(self._objects)):
            idnum = i + 1
            obj = self._objects[i]
            if obj is None:
                positions[idnum] = 0
                continue
            positions[idnum] = startdata + stream.tell()
            stream.write(pdf.b_(str(idnum) + " 0 obj\n"))
            key = None
            if self._encrypt_key is not None:
                pack1 = struct.pack("<i", i + 1)[:3]
                pack2 = struct.pack("<i", 0)[:2]
                key = self._encrypt_key + pack1 + pack2
                assert len(key) == (len(self._encrypt_key) + 5)
                md5_hash = hashlib.md5(key).digest()
                key = md5_hash[: min(16, len(self._encrypt_key) + 5)]
            obj.writeToStream(stream, key)
            stream.write(pdf.b_("\nendobj\n"))

        xref_location = startdata + stream.tell()
        if not prev.xrefstream:
            trailer = po.DictionaryObject()
        else:
            trailer = po.StreamObject()
            self._addObject(trailer)
        # xref table
        trailer.update(
            {
                po.NameObject("/Size"): po.NumberObject(len(self._objects) + 1),
                po.NameObject("/Root"): self.x_root,
                po.NameObject("/Prev"): po.NumberObject(prev.startxref),
                po.NameObject("/ID"): self._ID,
            }
        )

        if prev.isEncrypted:
            trailer[po.NameObject("/Encrypt")] = prev.trailer.raw_get("/Encrypt")

        if self.x_info:
            trailer[po.NameObject("/Info")] = self.x_info

        if not prev.xrefstream:
            stream.write(pdf.b_("xref\n"))
            positions[0] = 1
            keys = sorted(positions.keys())
            i = 0
            while i < len(keys):
                start = i
                while i < len(keys) and positions[keys[i]] != 0:
                    i += 1
                stream.write(pdf.b_("%d %d \n" % (keys[start], i - start)))
                i = start
                while i < len(keys) and positions[keys[i]] != 0:
                    if i == 0:
                        stream.write(pdf.b_("0000000000 65535 f \n"))
                    else:
                        stream.write(
                            pdf.b_("%010d %05d n \n" % (positions[keys[i]], 0))
                        )
                    i += 1
                while i < len(keys) and positions[keys[i]] == 0:
                    i += 1

            # trailer
            stream.write(pdf.b_("trailer\n"))
            trailer.writeToStream(stream, None)
        else:

            def pack(offset):
                return struct.pack(">q", offset)

            dataindex = ["0 1"]
            dataxref = [b"\x00" + pack(0)]
            keys = sorted(positions.keys())
            i = 0
            while i < len(keys):
                off = positions[keys[i]]
                if off != 0:
                    start = i
                    while i < len(keys) and positions[keys[i]] != 0:
                        dataxref.append(b"\x01" + pack(positions[keys[i]]))
                        i += 1
                    dataindex.append("%d %d" % (keys[start], i - start))
                else:
                    i += 1
            dataindex = " ".join(dataindex)
            dataxref = b"".join(dataxref)
            trailer[po.NameObject("/Type")] = po.NameObject("/XRef")
            trailer[po.NameObject("/W")] = po.NameObject("[1 8 0]")
            trailer[po.NameObject("/Index")] = po.NameObject("[%s]" % dataindex)
            trailer._data = dataxref
            retval = trailer.flateEncode()
            trailer.update(retval)
            trailer._data = retval._data
            stream.write(pdf.b_("%d 0 obj\n" % (len(self._objects))))
            trailer.writeToStream(stream, None)
            stream.write(pdf.b_("\nendobj"))

        # eof
        stream.write(pdf.b_("\nstartxref\n%s\n%%%%EOF\n" % (xref_location)))

    def _extend(self, obj):
        stream = getattr(obj, "stream", None)
        if stream is not None:
            # stream = stream.encode("utf-16be")
            d = {"__streamdata__": stream, "/Length": len(stream)}
            d.update(obj)
            dct = pdf.StreamObject.initializeFromDictionary(d)
            if "/Filter" in obj and obj["/Filter"] == "/FlatDecode":
                del dct["/Filter"]
                dct = dct.flateEncode()
        else:
            dct = pdf.DictionaryObject()
        for k, v in obj.items():
            if isinstance(v, pdf.DictionaryObject):
                if v.indirect:
                    v = self._extend(v)
                    v = self._addObject(v)
                else:
                    v = self._extend(v)
            elif isinstance(v, list):
                result = pdf.ArrayObject()
                for va in v:
                    if isinstance(va, pdf.DictionaryObject):
                        if va.indirect:
                            va = self._extend(va)
                            va = self._addObject(va)
                        else:
                            va = self._extend(va)
                    result.append(va)
                v = result
            dct[k] = v
        return dct

    def makepdf(self, prev, udct, algomd, zeros):
        catalog = prev.trailer["/Root"]
        size = prev.trailer["/Size"]
        pages = catalog["/Pages"].getObject()
        page0ref = prev.getPage(udct.get("sigpage", 0)).indirectRef

        self._objects = []
        while len(self._objects) < size - 1:
            self._objects.append(None)

        obj13 = po.DictionaryObject()
        obj13ref = self._addObject(obj13)
        obj12 = po.DictionaryObject()
        obj12ref = self._addObject(obj12)

        obj12.update(
            {
                po.NameObject("/Type"): po.NameObject("/Sig"),
                po.NameObject("/Filter"): po.NameObject("/Adobe.PPKLite"),
                po.NameObject("/SubFilter"): po.NameObject("/adbe.pkcs7.detached"),
                po.NameObject("/Name"): po.createStringObject(udct["contact"]),
                po.NameObject("/Location"): po.createStringObject(udct["location"]),
                po.NameObject("/Reason"): po.createStringObject(udct["reason"]),
                po.NameObject("/M"): po.createStringObject(udct["signingdate"]),
                po.NameObject("/Contents"): UnencryptedBytes(zeros),
                po.NameObject("/ByteRange"): po.ArrayObject(
                    [
                        WNumberObject(0),
                        WNumberObject(0),
                        WNumberObject(0),
                        WNumberObject(0),
                    ]
                ),
            }
        )
        obj13.update(
            {
                po.NameObject("/FT"): po.NameObject("/Sig"),
                po.NameObject("/Type"): po.NameObject("/Annot"),
                po.NameObject("/Subtype"): po.NameObject("/Widget"),
                po.NameObject("/F"): po.NumberObject(udct.get("sigflagsft", 132)),
                po.NameObject("/T"): EncodedString(udct.get("sigfield", "Signature1")),
                po.NameObject("/V"): obj12ref,
                po.NameObject("/P"): page0ref,
                po.NameObject("/Rect"): po.ArrayObject(
                    [
                        po.FloatObject(0.0),
                        po.FloatObject(0.0),
                        po.FloatObject(0.0),
                        po.FloatObject(0.0),
                    ]
                ),
            }
        )

        box = udct.get("signaturebox", None)
        if box is not None:
            from endesive.pdf.PyPDF2_annotate.annotations.text import FreeText
            from endesive.pdf.PyPDF2_annotate.annotations.image import Image
            from endesive.pdf.PyPDF2_annotate.config.appearance import Appearance
            from endesive.pdf.PyPDF2_annotate.config.location import Location
            from endesive.pdf.PyPDF2_annotate.util.geometry import identity

            annotationtext = udct.get("signature", None)
            x1, y1, x2, y2 = box
            if annotationtext is not None:
                annotation = FreeText(
                    Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0),
                    Appearance(
                        fill=[0, 0, 0],
                        stroke_width=1,
                        wrap_text=udct.get('text', {}).get('wraptext', True),
                        font_size=udct.get('text', {}).get('fontsize', 12),
                        text_align=udct.get('text', {}).get('textalign', 'left'),
                        line_spacing=udct.get('text', {}).get('linespacing', 1.2),
                        content=annotationtext,
                    ),
                )
                names = ("BS", "C", "Contents", "DA")
                if not udct.get("sigbutton", False):
                    obj13[po.NameObject("/Subtype")] = po.NameObject("/FreeText")
            else:
                ap = Appearance()
                ap.image = udct["signature_img"]
                annotation = Image(Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0), ap)
                if not udct.get("sigbutton", False):
                    names = (
                        #
                        "Subtype",
                    )
                else:
                    names = ()

            pdfa = annotation.as_pdf_object(identity(), page=page0ref)
            objapn = self._extend(pdfa["/AP"]["/N"])
            objapnref = self._addObject(objapn)

            for name in names + (
                "Rect",
                # "Subtype",
            ):
                key = po.NameObject("/" + name)
                v = pdfa[key]
                obj13[key] = v

            objap = po.DictionaryObject()
            objap[po.NameObject("/N")] = objapnref
            obj13.update(
                {
                    po.NameObject("/AP"): objap,
                    po.NameObject("/SM"): po.createStringObject("TabletPOSinline"),
                }
            )

            page0 = page0ref.getObject()
            annots = po.ArrayObject([obj13ref])
            if "/Annots" in page0:
                page0annots = page0["/Annots"]
                if isinstance(page0annots, po.IndirectObject):
                    annots.insert(0, page0annots)
                elif isinstance(page0annots, po.ArrayObject):
                    annots = page0annots
                    annots.append(obj13ref)
            page0.update({po.NameObject("/Annots"): annots})
            self._objects[page0ref.idnum - 1] = page0

        if udct.get("sigandcertify", False) and "/Perms" not in catalog:
            obj10 = po.DictionaryObject()
            obj10ref = self._addObject(obj10)
            obj11 = po.DictionaryObject()
            obj11ref = self._addObject(obj11)
            obj14 = po.DictionaryObject()
            obj14ref = self._addObject(obj14)
            obj14.update({po.NameObject("/DocMDP"): obj12ref})
            obj10.update(
                {
                    po.NameObject("/Type"): po.NameObject("/TransformParams"),
                    po.NameObject("/P"): po.NumberObject(udct.get("sigflags", 3)),
                    po.NameObject("/V"): po.NameObject("/1.2"),
                }
            )
            obj11.update(
                {
                    po.NameObject("/Type"): po.NameObject("/SigRef"),
                    po.NameObject("/TransformMethod"): po.NameObject("/DocMDP"),
                    po.NameObject("/DigestMethod"): po.NameObject("/" + algomd.upper()),
                    po.NameObject("/TransformParams"): obj10ref,
                }
            )
            obj12[po.NameObject("/Reference")] = po.ArrayObject([obj11ref])
            catalog[po.NameObject("/Perms")] = obj14ref

        if "/AcroForm" in catalog:
            form = catalog["/AcroForm"].getObject()
            if "/Fields" in form:
                fields = form["/Fields"]
            else:
                fields = po.ArrayObject()
            fields.append(obj13ref)
            form.update(
                {
                    po.NameObject("/Fields"): fields,
                    po.NameObject("/SigFlags"): po.NumberObject(
                        udct.get("sigflags", 3)
                    ),
                }
            )
            formref = catalog.raw_get("/AcroForm")
            if isinstance(formref, po.IndirectObject):
                self._objects[formref.idnum - 1] = form
                form = formref
        else:
            form = po.DictionaryObject()
            form.update(
                {
                    po.NameObject("/Fields"): po.ArrayObject([obj13ref]),
                    po.NameObject("/SigFlags"): po.NumberObject(
                        udct.get("sigflags", 3)
                    ),
                }
            )
        catalog[po.NameObject("/AcroForm")] = form

        if "/Metadata" in catalog:
            catalog[po.NameObject("/Metadata")] = catalog.raw_get("/Metadata")

        x_root = prev.trailer.raw_get("/Root")
        self._objects[x_root.idnum - 1] = catalog
        self.x_root = po.IndirectObject(x_root.idnum, 0, self)
        self.x_info = prev.trailer.get("/Info")

    def sign(
        self,
        datau,
        udct,
        key,
        cert,
        othercerts,
        algomd,
        hsm,
        timestampurl,
        timestampcredentials=None,
        timestamp_req_options=None,
    ):
        startdata = len(datau)

        fi = io.BytesIO(datau)

        # read end decrypt
        prev = pdf.PdfFileReader(fi)
        if prev.isEncrypted:
            rc = prev.decrypt(udct["password"])
        else:
            rc = 0

        # digest method must remain unchanged from prevoius signatures
        obj = prev.trailer
        for k in ("/Root", "/Perms", "/DocMDP", "/Reference"):
            if k in obj:
                obj = obj[k]
                if isinstance(obj, po.ArrayObject):
                    obj = obj[0]
                obj = obj.getObject()
            else:
                obj = None
                break
        if obj is not None:
            algomd = obj["/DigestMethod"][1:].lower()

        # produce smaller signatures, but must be signed twice
        aligned = udct.get("aligned", 0)
        if aligned:
            zeros = b"00" * aligned
        else:
            md = getattr(hashlib, algomd)().digest()
            contents = signer.sign(
                None,
                key,
                cert,
                othercerts,
                algomd,
                True,
                md,
                hsm,
                False,
                timestampurl,
                timestampcredentials,
                timestamp_req_options,
            )
            zeros = contents.hex().encode("utf-8")

        self.makepdf(prev, udct, algomd, zeros)

        # if document was encrypted, encrypt this version too
        if prev.isEncrypted:
            self.encrypt(prev, udct["password"], rc)
        else:
            self._encrypt_key = None

        # ID[0] is used in password protection, must be unchanged
        ID = prev.trailer.get("/ID", None)
        if ID is None:
            ID = hashlib.md5(repr(time.time()).encode()).digest()
        else:
            ID = ID[0]
            if isinstance(ID, str):
                ID = ID.encode()
        self._ID = po.ArrayObject(
            [
                po.ByteStringObject(ID),
                po.ByteStringObject(
                    hashlib.md5(repr(random.random()).encode()).digest()
                ),
            ]
        )

        fo = io.BytesIO()
        self.write(fo, prev, startdata)
        datas = fo.getvalue()

        br = [0, 0, 0, 0]
        bfrom = (b"[ " + b" ".join([WNumberObject.Format] * 4) + b" ]") % tuple(br)

        pdfbr1 = datas.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = [
            0,
            startdata + pdfbr1 - 1,
            startdata + pdfbr2 + 1,
            len(datas) - pdfbr2 - 1,
        ]
        bto = b"[%d %d %d %d]" % tuple(br)
        bto += b" " * (len(bfrom) - len(bto))
        assert len(bfrom) == len(bto)
        datas = datas.replace(bfrom, bto, 1)

        md = getattr(hashlib, algomd)()
        md.update(datau)
        b1 = datas[: br[1] - startdata]
        b2 = datas[br[2] - startdata :]
        md.update(b1)
        md.update(b2)
        md = md.digest()

        contents = signer.sign(
            None,
            key,
            cert,
            othercerts,
            algomd,
            True,
            md,
            hsm,
            False,
            timestampurl,
            timestampcredentials,
            timestamp_req_options,
        )
        contents = contents.hex().encode("utf-8")
        if aligned:
            nb = len(zeros) - len(contents)
            contents += b"0" * nb
        assert len(zeros) == len(contents)

        datas = datas.replace(zeros, contents, 1)

        return datas


def sign(
    datau,
    udct,
    key,
    cert,
    othercerts,
    algomd="sha1",
    hsm=None,
    timestampurl=None,
    timestampcredentials=None,
    timestamp_req_options=None,
):
    """
    parameters:
        datau: pdf bytes being signed
        udct: dictionary with signing parameters
            aligned: int                if 0 then precompute size of signature, but first fake data will be signed
                                        !=0 number of hexbytes (00) reserved for signature,
                                            must be equal or greather than hex representation of signature
                                            probably 16384 will be sufficient ....
            sigflags: int               default:3 1,2,3 - flags for acroform
            sigflagsft: int             default:132 - flags for annotation widget from pdf 12.5.3
            sigpage: int                default:0 - page on which signature should appear
            sigbutton: bool             default:False
            sigfield: string            default:Signature1
            sigandcertify: bool         default:False
                                                False - sign only document
                                                True  - sign and certify document
            signaturebox: box|None      default:None - where to put signature image/string on selected page
            signature: string                   if box is not None then it should be latin1 encodable string
            signature_img: string|pil_image     if box is not None and string is None then it should be
                                                    pil image instance or
                                                    image file name or
                                                    byte array of image
            contact: string             required info about the person signing the document
            location:string             required info about location of the person signing the document
            signingdate: string         required info about signing time eg: now.strftime('D:%Y%m%d%H%M%S+00\'00\'')
            reason: string              required info about reason for signing the document
            password: string            required if the document is password protected, signing it also requires that password
            text: dict                  text attributes
                                            wraptext=True, fontsize:12, textalign:'left', linespacing:1.2
        key: cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey - private key used to sign the document
        cert: cryptography.x509.Certificate - certificate associated with the key
        othercerts: list of cryptography.x509.Certificate to be saved with the signed document,
            e.g.: a list of intermediate certificates used to confirm the authenticity of the certificate used in the signature
        algomd:string                   default: sha1 - name of the hashing algorithm used to calculate
                                            the hash of the document being signed e.g.: sha1, sha256, sha384, sha512, ripemd160
        hsm: an instance of endesive.hsm.HSM class used to sign using a hardware token or None
        timestampurl: timestamp server URL or None
        timestampcredentials:Dict username and password for authentication against timestamp server. Default: None
        timestamp_req_options: Dict to set options to the POST http call against the timestamp server. Default: None

    returns: bytes ready for writing after unsigned pdf document containing its electronic signature
    """
    cls = SignedData()
    return cls.sign(
        datau,
        udct,
        key,
        cert,
        othercerts,
        algomd,
        hsm,
        timestampurl,
        timestampcredentials,
        timestamp_req_options,
    )

