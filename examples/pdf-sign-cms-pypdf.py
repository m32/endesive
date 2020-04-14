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


class Main(pdf.PdfFileWriter):
    annottext = True
    annotbutton = True

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
        positions = {2: 0}
        for i in range(2, len(self._objects)):
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
                po.NameObject("/Info"): self.x_info,
                po.NameObject("/Prev"): po.NumberObject(prev.startxref),
                po.NameObject("/ID"): self._ID,
            }
        )
        if prev.isEncrypted:
            trailer[po.NameObject("/Encrypt")] = prev.trailer.raw_get("/Encrypt")
        if not prev.xrefstream:
            stream.write(pdf.b_("xref\n"))
            stream.write(pdf.b_("0 1\n"))
            stream.write(pdf.b_("0000000000 65535 f \n"))
            keys = sorted(positions.keys())
            i = 0
            while i < len(keys):
                off = positions[keys[i]]
                if off == 0:
                    while i < len(keys) and positions[keys[i]] == 0:
                        i += 1
                    start = i
                    while i < len(keys) and positions[keys[i]] != 0:
                        i += 1
                    stream.write(pdf.b_("%d %d \n" % (keys[start], i - start)))
                    i = start
                    continue
                else:
                    stream.write(pdf.b_("%010d %05d n \n" % (off, 0)))
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
                    stop = i
                    dataindex.append("%d %d" % (keys[start], stop - start))
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
            d = {"__streamdata__": stream, "/Length": len(stream)}
            d.update(obj)
            dct = pdf.StreamObject.initializeFromDictionary(d)
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
                v = pdf.ArrayObject(v)
            dct[k] = v
        return dct

    def makepdf(self, prev, algomd, zeros):
        catalog = prev.trailer["/Root"]
        size = prev.trailer["/Size"]
        pages = catalog["/Pages"].getObject()
        page0ref = pages["/Kids"][0]

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
                po.NameObject("/Name"): EncodedString("Example User"),
                po.NameObject("/Location"): EncodedString("Los Angeles, CA"),
                po.NameObject("/Reason"): EncodedString("Testing"),
                po.NameObject("/M"): EncodedString("D:20200317214832+01'00'"),
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
                po.NameObject("/F"): po.NumberObject(132),
                po.NameObject("/T"): EncodedString("Signature1"),
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

        if self.annottext:
            from endesive.pdf.PyPDF2_annotate.annotations.text import FreeText
            from endesive.pdf.PyPDF2_annotate.annotations.image import Image
            from endesive.pdf.PyPDF2_annotate.config.appearance import Appearance
            from endesive.pdf.PyPDF2_annotate.config.location import Location
            from endesive.pdf.PyPDF2_annotate.util.geometry import identity

            annotationtext = None
            #annotationtext = "User signature text"
            x1, y1, x2, y2 = (470, 0, 570, 100)
            if annotationtext is not None:
                annotation = FreeText(
                    Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0),
                    Appearance(
                        fill=[0, 0, 0],
                        stroke_width=1,
                        wrap_text=True,
                        font_size=12,
                        content=annotationtext,
                    ),
                )
                names = ("BS", "C", "Contents", "DA")
                if not self.annotbutton:
                    obj13[po.NameObject("/Subtype")] = po.NameObject("/FreeText")
            else:
                from PIL import Image as PILImage

                image = PILImage.open("signature_test.png")
                ap = Appearance()
                ap.image = image
                annotation = Image(Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0), ap)
                if not self.annotbutton:
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

        if "/Perms" not in catalog:
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
                    po.NameObject("/P"): po.NumberObject(2),
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
                    po.NameObject("/SigFlags"): po.NumberObject(3),
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
                    po.NameObject("/SigFlags"): po.NumberObject(3),
                }
            )
        catalog[po.NameObject("/AcroForm")] = form

        if "/Metadata" in catalog:
            catalog[po.NameObject("/Metadata")] = catalog.raw_get("/Metadata")

        x_root = prev.trailer.raw_get("/Root")
        self._objects[x_root.idnum - 1] = catalog
        self.x_root = po.IndirectObject(x_root.idnum, 0, self)
        self.x_info = prev.trailer.raw_get("/Info")

    def sign(self, md, algomd):
        tspurl = "http://public-qlts.certum.pl/qts-17"
        tspurl = None
        with open("demo2_user1.p12", "rb") as fp:
            p12 = pkcs12.load_key_and_certificates(
                fp.read(), b"1234", backends.default_backend()
            )
        contents = signer.sign(
            None, p12[0], p12[1], p12[2], algomd, True, md, None, False, tspurl
        )
        return contents

    def main(self, fname, password):
        with open(fname, "rb") as fi:
            datau = fi.read()
        startdata = len(datau)

        fi = io.BytesIO(datau)

        prev = pdf.PdfFileReader(fi)
        if prev.isEncrypted:
            rc = prev.decrypt(password)
        else:
            rc = 0

        algomd = "sha1"
        aligned = False

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

        if aligned:
            zeros = b"0" * 37888
        else:
            md = getattr(hashlib, algomd)().digest()
            contents = self.sign(md, algomd)
            zeros = contents.hex().encode("utf-8")

        self.makepdf(prev, algomd, zeros)

        if prev.isEncrypted:
            self.encrypt(prev, password, rc)
        else:
            self._encrypt_key = None
        ID = prev.trailer.get("/ID", None)
        if ID is None:
            ID = po.ByteStringObject(hashlib.md5(repr(time.time()).encode()).digest())
        else:
            ID = ID[0]
        self._ID = po.ArrayObject(
            [
                ID,
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

        contents = self.sign(md, algomd)
        contents = contents.hex().encode("utf-8")
        if aligned:
            nb = len(zeros) - len(contents)
            contents += b"0" * nb
        datas = datas.replace(zeros, contents, 1)

        fname = fname.replace(".pdf", "-signed-pypdf.pdf")
        with open(fname, "wb") as fp:
            fp.write(datau)
            fp.write(datas)


def main():
    if len(sys.argv) > 1:
        cls = Main()
        cls.main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
    else:
        cls = Main()
        cls.main("pdf.pdf", "")

        cls = Main()
        cls.main("pdf-encrypted.pdf", "1234")


main()
