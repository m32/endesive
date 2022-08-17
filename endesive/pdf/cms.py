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
            keylen = 128 // 8
        else:
            rev = 2
            keylen = 40 // 8
        P = encrypt["/P"].getObject()
        O = encrypt["/O"].getObject()
        ID_1 = prev.trailer["/ID"].getObject()[0]
        real_U = encrypt["/U"].getObject().original_bytes
        if rev == 2:
            U, key = pdf._alg34(password, O, P, ID_1)
        else:
            assert rev == 3
            U, key = pdf._alg35(
                password,
                rev,
                keylen,
                O,
                P,
                ID_1,
                encrypt.get("/EncryptMetadata", pdf.BooleanObject(False)).getObject(),
            )
            U, real_U = U[:16], real_U[:16]
        assert U == real_U
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

    def _make_signature(self, Contents=None, Type=None, SubFilter=None):
        sig = po.DictionaryObject()
        sig_ref = self._addObject(sig)
        sig.update(
            {
                po.NameObject("/Type"): Type,
                po.NameObject("/Filter"): po.NameObject("/Adobe.PPKLite"),
                po.NameObject("/SubFilter"): SubFilter,
                po.NameObject("/ByteRange"): po.ArrayObject(
                    [
                        WNumberObject(0),
                        WNumberObject(0),
                        WNumberObject(0),
                        WNumberObject(0),
                    ]
                ),
                po.NameObject("/Contents"): Contents,
            }
        )
        return sig, sig_ref

    def _make_sig_annotation(self, F=None, Vref=None, T=None, Pref=None):
        annot = po.DictionaryObject()
        annot_ref = self._addObject(annot)
        annot.update(
            {
                po.NameObject("/FT"): po.NameObject("/Sig"),
                po.NameObject("/Type"): po.NameObject("/Annot"),
                po.NameObject("/Subtype"): po.NameObject("/Widget"),
                po.NameObject("/F"): F,
                po.NameObject("/T"): T,
                po.NameObject("/V"): Vref,
                po.NameObject("/P"): Pref,
                # For an invisible signature, /Rect should be a size 0 box
                # Defaulting to that
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
        return annot, annot_ref

    def makepdf(self, prev, udct, algomd, zeros, cert, **params):
        catalog = prev.trailer["/Root"]
        size = prev.trailer["/Size"]
        pages = catalog["/Pages"].getObject()
        page0ref = prev.getPage(udct.get("sigpage", 0)).indirectRef

        self._objects = []
        while len(self._objects) < size - 1:
            self._objects.append(None)

        ##        if params['mode'] == 'timestamp':
        ##            # deal with extensions
        ##            if '/Extensions' not in catalog:
        ##                extensions = po.DictionaryObject()
        ##            else:
        ##                extensions = catalog['/Extensions']
        ##
        ##            if '/ESIC' not in extensions:
        ##                extensions.update({
        ##                    po.NameObject("/ESIC"): po.DictionaryObject({
        ##                        po.NameObject('/BaseVersion'): po.NameObject('/1.7'),
        ##                        po.NameObject('/ExtensionLevel'): po.NumberObject(1),
        ##                        })
        ##                    })
        ##            else:
        ##                esic = extensions['/ESIC']
        ##                major, minor = esic['/BaseVersion'].lstrip('/').split('.')
        ##                if int(major) < 1 or int(minor) < 7:
        ##                    esic.update({
        ##                        po.NameObject('/BaseVersion'): po.NameObject('/1.7'),
        ##                        po.NameObject('/ExtensionLevel'): po.NumberObject(1),
        ##                        })
        ##            catalog.update({
        ##                po.NameObject('/Extensions'): extensions
        ##                })

        # obj12 is the digital signature
        obj12, obj12ref = self._make_signature(
            Type=po.NameObject("/Sig"),
            SubFilter=po.NameObject("/adbe.pkcs7.detached"),
            Contents=UnencryptedBytes(zeros),
        )

        if params["mode"] == "timestamp":
            # obj12 is a timestamp this time
            obj12.update(
                {
                    po.NameObject("/Type"): po.NameObject("/DocTimeStamp"),
                    po.NameObject("/SubFilter"): po.NameObject("/ETSI.RFC3161"),
                    po.NameObject("/V"): po.NumberObject(0),
                }
            )
        else:
            obj12.update(
                {
                    po.NameObject("/Name"): po.createStringObject(udct["contact"]),
                    po.NameObject("/Location"): po.createStringObject(udct["location"]),
                    po.NameObject("/Reason"): po.createStringObject(udct["reason"]),
                }
            )
            if params.get("use_signingdate"):
                obj12.update(
                    {po.NameObject("/M"): po.createStringObject(udct["signingdate"])}
                )

        # obj13 is a combined AcroForm Sig field with Widget annotation
        new_13 = True
        # obj13 = po.DictionaryObject()
        if udct.get("signform", False):
            # Attaching signature to existing field in AcroForm
            if "/AcroForm" in catalog:
                form = catalog["/AcroForm"].getObject()
                if "/Fields" in form:
                    fields = form["/Fields"].getObject()
                    obj13ref = [
                        f
                        for f in fields
                        if f.getObject()["/T"] == udct.get("sigfield", "Signature1")
                    ][0]
                    obj13 = obj13ref.getObject()
                    self._objects[obj13ref.idnum - 1] = obj13
                    new_13 = False

        # box is coordinates of the annotation to fill
        box = udct.get("signaturebox", None)

        if new_13:
            obj13, obj13ref = self._make_sig_annotation(
                F=po.NumberObject(udct.get("sigflagsft", 132)),
                T=EncodedString(udct.get("sigfield", "Signature1")),
                Vref=obj12ref,
                Pref=page0ref,
            )
        else:
            # original obj13 is a merged SigField/SigAnnot
            # Setting /V on the AcroForm field sets the signature
            # for the field
            obj13.update({po.NameObject("/V"): obj12ref})
            # fill the existing signature field annotation,
            # ignore any other location
            if "/Rect" in obj13:
                box = [float(f) for f in obj13["/Rect"]]

        # add an annotation if there is a field to fill
        if box is not None:
            from endesive.pdf.PyPDF2_annotate.annotations.signature import Signature
            from endesive.pdf.PyPDF2_annotate.config.appearance import Appearance
            from endesive.pdf.PyPDF2_annotate.config.location import Location
            from endesive.pdf.PyPDF2_annotate.util.geometry import identity

            x1, y1, x2, y2 = box
            annotation = Signature(
                Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0), Appearance()
            )
            if "signature" in udct:
                # Plain text signature with the default font
                # text to render is contained in udct['signature']
                # font parameters are in udct['signature']['text']
                annotationtext = udct["signature"]
                wrap_text = udct.get("text", {}).get("wraptext", True)
                font_size = udct.get("text", {}).get("fontsize", 12)
                text_align = udct.get("text", {}).get("textalign", "left")
                line_spacing = udct.get("text", {}).get("linespacing", 1.2)

                annotation.add_default_font()
                annotation.set_signature_appearance(
                    ["fill_colour", 0, 0, 0],
                    ["font", "default", font_size],
                    [
                        "text_box",
                        annotationtext,
                        "default",
                        0,
                        0,
                        x2 - x1,
                        y2 - y1,
                        font_size,
                        wrap_text,
                        text_align,
                        "middle",
                        line_spacing,
                    ],
                )
            elif "signature_img" in udct:
                # Simple image signature, stretches to fit the box
                # image to render is contained in udct['signature_image']
                annotation.add_image(udct["signature_img"], "Image")
                annotation.set_signature_appearance(
                    [
                        "image",
                        "Image",
                        0,
                        0,
                        x2 - x1,
                        y2 - y1,
                        udct.get("signature_img_distort", True),
                        udct.get("signature_img_centred", False),
                    ]
                )
            elif "signature_appearance" in udct:
                # Adobe-inspired signature with text and images
                # Parameters are contained in udct['signature_appearance']
                # If a field is included in the display list, that field
                # will be contained in the annotation.
                #
                # Text and border are the colour specified by outline,
                # and border is the the inset distance from the outer
                # edge of the annotation.  The R G B values range between
                # 0 and 1.
                #
                # Icon is an image to display above the background and
                # border at the left-hand side of the anntoation.  If
                # there is no text, it is centred.
                #
                # The text block is left-aligned to the right of the icon
                # image.  If there is no image, the text is left-aliged
                # with the left-hand border of the annotation
                #
                # display fields:
                #   CN, DN, date, contact, reason, location
                #
                # Dict format:
                #   appearance = dict(
                #       background = Image with alpha / None,
                #       icon = Image with alpha / None,
                #       labels = bool,
                #       display = list,
                #       software = str,
                #       outline = [R, G, B],
                #       border = int,
                #       )
                sig = {}
                for f in ("background", "icon", "labels", "border", "outline"):
                    if f in udct["signature_appearance"]:
                        sig[f] = udct["signature_appearance"][f]

                toggles = udct["signature_appearance"].get("display", [])
                for f in ("contact", "reason", "location", "contact", "signingdate"):
                    if f in toggles:
                        sig[f] = udct.get(f, "{} unknown".format(f))
                if "date" in toggles:
                    sig["date"] = udct["signingdate"]
                if "CN" in toggles:
                    from cryptography.x509 import ObjectIdentifier

                    sig["CN"] = cert.subject.get_attributes_for_oid(
                        ObjectIdentifier("2.5.4.3")
                    )[0].value
                if "DN" in toggles:
                    sig["DN"] = cert.subject.rfc4514_string()
                annotation.simple_signature(sig)
            else:
                # Manual signature annotation creation
                #
                # Make your own appearance with an arbitrary number of
                # images and fonts
                if "manual_images" in udct:
                    for name, img in udct["manual_images"].items():
                        annotation.add_image(img, name=name)
                if "manual_fonts" in udct:
                    for name, path in udct["manual_fonts"].items():
                        annotation.add_ttf_font(path, name=name)
                annotation.add_default_font()
                annotation.set_signature_appearance(*udct["signature_manual"])

            pdfa = annotation.as_pdf_object(identity(), page=page0ref)
            objapn = self._extend(pdfa["/AP"]["/N"])
            objapnref = self._addObject(objapn)

            objap = po.DictionaryObject()
            objap[po.NameObject("/N")] = objapnref
            obj13.update(
                {
                    po.NameObject("/Rect"): po.ArrayObject(
                        [
                            po.FloatObject(x1),
                            po.FloatObject(y1),
                            po.FloatObject(x2),
                            po.FloatObject(y2),
                        ]
                    ),
                    po.NameObject("/AP"): objap,
                    # po.NameObject("/SM"): po.createStringObject("TabletPOSinline"),
                }
            )

            page0 = page0ref.getObject()
            if new_13:
                annots = po.ArrayObject([obj13ref])
                if "/Annots" in page0:
                    page0annots = page0["/Annots"]
                    if isinstance(page0annots, po.IndirectObject):
                        annots.insert(0, page0annots)
                    elif isinstance(page0annots, po.ArrayObject):
                        annots = page0annots
                        annots.append(obj13ref)
            else:
                annots = page0["/Annots"]
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
                old_field_names = [f.getObject()["/T"] for f in fields]
            else:
                fields = po.ArrayObject()
                old_field_names = []
            if udct.get("auto_sigfield", False) and obj13["/T"] in old_field_names:
                name_base = udct.get("sigfield", "Signature1")
                checklist = [
                    f[len(name_base) :]
                    for f in old_field_names
                    if f.startswith(name_base)
                ]
                for i in range(1, len(checklist) + 1):
                    suffix = "_{}".format(i)
                    if suffix in checklist:
                        continue

                    new_name = "{}{}".format(name_base, suffix)
                    obj13.update({po.NameObject("/T"): EncodedString(new_name)})
                    break

            old_flags = int(form.get("/SigFlags", 0))
            new_flags = int(form.get("/SigFlags", 0)) | udct.get("sigflags", 3)
            if new_13:
                fields.append(obj13ref)
                form.update(
                    {
                        po.NameObject("/Fields"): fields,
                        po.NameObject("/SigFlags"): po.NumberObject(new_flags),
                    }
                )
            elif new_flags > old_flags:
                form.update({po.NameObject("/SigFlags"): po.NumberObject(new_flags)})
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
        timestampurl=None,
        timestampcredentials=None,
        timestamp_req_options=None,
        mode="sign",
        ocspurl=None,
        ocspissuer=None,
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
            if mode == "timestamp":
                contents = signer.timestamp(
                    None,
                    algomd,
                    timestampurl,
                    timestampcredentials,
                    timestamp_req_options,
                    prehashed=md,
                )[0]["values"][0].dump()
            else:
                attrs = udct.get("attrs", True)
                contents = signer.sign(
                    None,
                    key,
                    cert,
                    othercerts,
                    algomd,
                    attrs,
                    md,
                    hsm,
                    False,
                    timestampurl,
                    timestampcredentials,
                    timestamp_req_options,
                    ocspurl,
                    ocspissuer,
                )
            zeros = contents.hex().encode("utf-8")

        params = {"mode": mode}
        if not timestampurl:
            params["use_signingdate"] = True

        self.makepdf(prev, udct, algomd, zeros, cert, **params)

        # if document was encrypted, encrypt this version too
        if prev.isEncrypted:
            self.encrypt(prev, udct["password"], rc)
        else:
            self._encrypt_key = None

        # ID[0] is used in password protection, must be unchanged
        ID = prev.trailer.get("/ID", None)
        if ID is None:
            ID = udct.get('id') or hashlib.md5(repr(time.time()).encode()).digest()
        else:
            ID = ID.getObject()[0].original_bytes
        newID = udct.get("newid", repr(random.random()))
        self._ID = po.ArrayObject(
            [
                po.ByteStringObject(ID),
                po.ByteStringObject(
                    hashlib.md5(newID.encode()).digest()
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

        if mode == "timestamp":
            contents = signer.timestamp(
                None,
                algomd,
                timestampurl,
                timestampcredentials,
                timestamp_req_options,
                prehashed=md,
            )[0]["values"][0].dump()
        else:
            attrs = udct.get("attrs", True)
            contents = signer.sign(
                None,
                key,
                cert,
                othercerts,
                algomd,
                attrs,
                md,
                hsm,
                False,
                timestampurl,
                timestampcredentials,
                timestamp_req_options,
                ocspurl,
                ocspissuer,
            )
        contents = contents.hex().encode("utf-8")
        if aligned:
            nb = len(zeros) - len(contents)
            contents += b"0" * nb
        assert len(zeros) == len(contents)

        datas = datas.replace(zeros, contents, 1)

        return datas


def timestamp(
    datau,
    udct,
    algomd="sha1",
    timestampurl=None,
    timestampcredentials=None,
    timestamp_req_options=None,
):
    """
    parameters:
        datau: pdf bytes being timestamped
        udct: dictionary with signing parameters
            Same paramaters as the sign method.  The following parameters
            should not be used as they are either unused or conflict with
            normal timestamping:

            - signform
            - sigandcertify
            - contact
            - location
            - signingdate
            - reason

            Timestamping also does not typically use signature appearances.
            The following appearance options should probably be omitted,
            but do not conflict with the normal timestamping operations.

            - signaturebox
            - signature
            - signature_img
            - signature_img_distort
            - signature_img_centred
            - signature_appearance
            - signature_manual
            - manual_fonts
            - manual_images
        algomd:string                   default: sha1 - name of the hashing algorithm used to calculate
                                            the hash of the document being signed e.g.: sha1, sha256, sha384, sha512, ripemd160
        hsm: an instance of endesive.hsm.HSM class used to sign using a hardware token or None
        timestampurl: timestamp server URL or None
        timestampcredentials:Dict username and password for authentication against timestamp server. Default: None
        timestamp_req_options: Dict to set options to the POST http call against the timestamp server. Default: None

    returns: bytes ready for writing after unsigned pdf document containing its electronic timestamp
    """

    cls = SignedData()
    return cls.sign(
        datau,
        udct,
        None,  # key,
        None,  # cert,
        None,  # othercerts,
        algomd,
        None,  # hsm,
        timestampurl,
        timestampcredentials,
        timestamp_req_options,
        mode="timestamp",
    )


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
    ocspurl=None,
    ocspissuer=None,
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
            sigfield: string            default:Signature1
            auto_sigfield: bool         default:False
                                                False - do not check for sigfield name conflicts
                                                True  - append and increment suffix to sigfield when a field
                                                        by the name of sigfield already exists in AcroForm
            signform: bool              default:False
                                                False - do not fill in an existing form's signature field
                                                True  - attach signature to the pre-existing Sig field by the
                                                        the name provided by sigfield in AcroForm.  Use with
                                                        signature or signature_img, will fill the signature
                                                        field's widget, ignoring signaturebox.
            sigandcertify: bool         default:False
                                                False - sign only document
                                                True  - sign and certify document
            signaturebox: box|None      default:None - where to put signature image/string on selected page
            signature: string                   if box is not None then it should be latin1 encodable string
            signature_img: string|pil_image     if box is not None and string is None then it should be
                                                    pil image instance or
                                                    image file name or
                                                    byte array of image
            signature_img_distort: bool default:True
                                                True  - do not maintain image aspect ratio, fill the
                                                        entire bounding box, distorting the image.
                                                        This is set to True to match the behaviour
                                                        of previous versions of endesive
                                                False - maintain image aspect ratio when fitting
                                                        image into the bounding box
            signature_img_centred: bool default:True
                                                True  - centre images within the bounding box when
                                                        image aspect ratio does not match that of
                                                        the bounding box
                                                False - do not centre image, position it at the
                                                        lower-left of the bounding box
            signature_appearance: dict  if box is not None then render a signature appearance that is
                                            configured by the dict.  See below for configuration
            signature_manual: list      if box is not None then render a manually-created signature
                                        apperance using the directives contained in this list
            manual_fonts: dict          fonts required by the manual signature appearance
            manual_images: dict         images required by the manual signature appearance
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
        ocsppurl: ocsp server URL or None
        ocspissuer: certificate of issuer or None

    returns: bytes ready for writing after unsigned pdf document containing its electronic signature

    Signature appearance:

    Adobe-inspired signature with text and images Parameters are contained
    in udct['signature_appearance']

    If a field is included in the display list, that field will be included
    in the annotation.  Its value is based upon what is in udct and the cert.
    Text and border are the colour specified by outline, and border is the
    the inset distance from the outer edge of the annotation.  The R G B
    values range between 0 and 1.

    Icon is an image to display above the background and border at the
    left-hand side of the anntoation.  If there is no text, it is centred.

    The text block is left-aligned to the right of the icon image.  If there
    is no image, the text is left-aliged with the left-hand border of the
    annotation

    display fields:
        CN, DN, date, contact, reason, location

    Dict format:
      appearance = dict(
          background = Image with alpha / None,
          icon = Image with alpha / None,
          labels = bool,
          display = list,
          software = str,
          outline = [R, G, B],
          border = int,
          )

    Signature manual:

    Manually set up your own signature appearance with arbitrary fonts and
    images.  The full list of directives can be seen in the template dict
    in endesive.pdf.PyPDF2_annotate.annotations.signatureaSignatureAppearance

    Coordinates are based off of the lower-left corner of the annotation

    manual_images is a dict of images that will be included in the annotation
    The keys are strings, and are the names to use when referring to the them
    in 'image' directives.

    manual_fonts is a dict of TrueType fonts that will be included in the
    annotation.  The keys are strings, and are the names to use when referring
    to the them in 'image' directives.  The values are the paths to the font
    files.  Do not use the name 'default' in this dict; it is treated
    specially.

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
        "sign",
        ocspurl,
        ocspissuer,
    )
