#!/usr/bin/env vpython3
import sys
import time
import random
import io
import datetime
import hashlib
import codecs
import struct
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
import pdfrw as pdf
from pdfrw import pdfwriter as pdfw
from endesive import signer


class PdfBasicObject(pdf.PdfObject):
    def __init__(self, data):
        self.data = data


class PdfHexBytes(pdf.PdfObject):
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return "<" + self.data.decode("utf-8") + ">"


class PdfNumber(PdfBasicObject):
    Format = "%d"

    def __str__(self):
        return self.Format % self.data


class PdfNumberB(PdfNumber):
    Format = "%08d"


class PdfNumberFloat(PdfNumber):
    Format = "%.5f"

    def __str__(self):
        s = (self.Format % self.data).rstrip("0").rstrip(".")
        return s


class PdfIndirect(tuple):
    def __str__(self):
        return "%d %d R" % self


class Signer(object):
    def __init__(self, fname, password):
        self.fname = fname
        self.password = password if password != "" else None
        self.compress = False
        self.objects = []
        with open(fname, "rb") as fi:
            self.datau = fi.read()
        self.startdata = len(self.datau)
        self.annotbutton = False
        s = b"startxref"
        i = self.datau.rfind(s)
        assert i != -1
        i += len(s)
        while self.datau[i] not in b"0123456789":
            i += 1
        j = i
        while self.datau[j] in b"0123456789":
            j += 1
        s = self.datau[i:j].decode()
        startprev = int(s, 10)
        self.startprev = startprev
        self.prev = pdf.PdfFileReader(
            fdata=self.datau, decrypt=(password is not None), password=password
        )

    def format_array(self, myarray):
        subarray = []
        bigarray = []
        count = 1000000
        for x in myarray:
            x = self.format(x)
            lenx = len(x) + 1
            count += lenx
            if count > 71:
                subarray = []
                bigarray.append(subarray)
                count = lenx
            subarray.append(x)
        return "[%s]" % "\n".join([" ".join(x) for x in bigarray])

    def format_dict(self, obj):
        if self.compress and obj.stream:
            pdfw.do_compress([obj])
        myarray = []
        for key, value in obj.iteritems():
            key = getattr(key, "encoded", None) or key
            key = self.format_obj(key)
            value = self.format(value)
            myarray.append(key + " " + value)
        result = "<<%s>>" % "\n".join(myarray)
        if obj.stream is not None:
            result = "%s\nstream\n%s\nendstream" % (result, obj.stream)
        return result

    def format_obj(self, obj):
        return str(obj)

    def format(self, obj):
        if isinstance(obj, pdf.PdfArray):
            return self.format_array(obj)
        elif isinstance(obj, pdf.PdfDict):
            return self.format_dict(obj)
        elif hasattr(obj, "indirect"):
            obj = getattr(obj, "encoded", None) or obj
        return self.format_obj(obj)

    def write(self, stream):
        positions = {}

        for i, x in enumerate(self.objects):
            if x is None:
                positions[i + 1] = 0
                continue
            positions[i + 1] = self.startdata + stream.tell()
            x = self.format(x)
            objstr = "%s 0 obj\n%s\nendobj\n" % (i + 1, x)
            stream.write(pdfw.convert_store(objstr))

        # xref table
        xref_location = self.startdata + stream.tell()
        stream.write(b"xref\n")
        stream.write(b"0 1\n")
        stream.write(b"0000000000 65535 f \n")
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
                stream.write(b"%d %d\n" % (keys[start], i - start))
                i = start
                off = positions[keys[i]]
            stream.write(b"%010d %05d n \n" % (off, 0))
            i += 1

        # trailer
        stream.write(b"trailer\n")
        objstr = self.format(self.trailer)
        stream.write(pdfw.convert_store(objstr))
        # eof
        stream.write(b"\nstartxref\n%d\n%%%%EOF\n" % xref_location)

    def addObject(self, obj):
        self.objects.append(obj)
        return PdfIndirect((len(self.objects), 0))

    def copyarray(self, obj):
        dct = pdf.PdfArray()
        for v in obj:
            if v.indirect:
                v = PdfIndirect(v.indirect)
            elif isinstance(v, pdf.PdfArray):
                v = self.copydict(v)
            elif isinstance(v, pdf.PdfDict):
                v = self.copydict(v)
            dct.append(v)
        return dct

    def copydict(self, obj):
        dct = pdf.PdfDict()
        for k, v in obj.iteritems():
            if v.indirect:
                v = PdfIndirect(v.indirect)
            elif isinstance(v, pdf.PdfArray):
                v = self.copyarray(v)
            elif isinstance(v, pdf.PdfDict):
                v = self.copydict(v)
            dct[k] = v
        return dct

    def extend(self, obj):
        dct = pdf.PdfDict()
        dct.stream = obj.stream
        for k, v in obj.iteritems():
            if isinstance(v, pdf.PdfDict):
                if not v.indirect:
                    v = self.extend(v)
                    v = self.addObject(v)
                else:
                    v = self.extend(v)
            elif isinstance(v, list):
                v = pdf.PdfArray(v)
            dct[k] = v
        return dct

    def makepdf(self, zeros):
        root = self.prev.Root
        size = int(self.prev.Size, 10)

        while len(self.objects) < size - 1:
            self.objects.append(None)

        page0 = self.copydict(root.Pages.Kids[0])
        page0ref = PdfIndirect(root.Pages.Kids[0].indirect)

        obj10 = pdf.PdfDict()
        obj10ref = self.addObject(obj10)
        obj11 = pdf.PdfDict()
        obj11ref = self.addObject(obj11)
        obj12 = pdf.PdfDict()
        obj12ref = self.addObject(obj12)
        obj13 = pdf.PdfDict()
        obj13ref = self.addObject(obj13)
        obj14 = pdf.PdfDict()
        obj14ref = self.addObject(obj14)

        obj10.update(
            {
                pdf.PdfName("Type"): pdf.PdfName("TransformParams"),
                pdf.PdfName("P"): PdfNumber(2),
                pdf.PdfName("V"): pdf.PdfName("1.2"),
            }
        )
        obj11.update(
            {
                pdf.PdfName("Type"): pdf.PdfName("SigRef"),
                pdf.PdfName("TransformMethod"): pdf.PdfName("DocMDP"),
                pdf.PdfName("DigestMethod"): pdf.PdfName("SHA1"),
                pdf.PdfName("TransformParams"): obj10ref,
            }
        )
        obj12.update(
            {
                pdf.PdfName("Type"): pdf.PdfName("Sig"),
                pdf.PdfName("Filter"): pdf.PdfName("Adobe.PPKLite"),
                pdf.PdfName("SubFilter"): pdf.PdfName("adbe.pkcs7.detached"),
                pdf.PdfName("Name"): pdf.PdfString.from_unicode("Example User"),
                pdf.PdfName("Location"): pdf.PdfString.from_unicode("Los Angeles, CA"),
                pdf.PdfName("Reason"): pdf.PdfString.from_unicode("Testing"),
                pdf.PdfName("M"): pdf.PdfString.from_unicode("D:20200317214832+01'00'"),
                pdf.PdfName("Reference"): pdf.PdfArray([obj11ref]),
                pdf.PdfName("Contents"): PdfHexBytes(zeros),
                pdf.PdfName("ByteRange"): pdf.PdfArray(
                    [PdfNumberB(0), PdfNumberB(0), PdfNumberB(0), PdfNumberB(0)]
                ),
            }
        )
        obj13.update(
            {
                pdf.PdfName("FT"): pdf.PdfName("Sig"),
                pdf.PdfName("Type"): pdf.PdfName("Annot"),
                pdf.PdfName("Subtype"): pdf.PdfName("Widget"),
                pdf.PdfName("F"): PdfNumber(132),
                pdf.PdfName("T"): pdf.PdfString.from_unicode("Signature1"),
                pdf.PdfName("V"): obj12ref,
                pdf.PdfName("P"): page0ref,
                pdf.PdfName("Rect"): pdf.PdfArray(
                    [
                        PdfNumberFloat(0.0),
                        PdfNumberFloat(0.0),
                        PdfNumberFloat(0.0),
                        PdfNumberFloat(0.0),
                    ]
                ),
            }
        )
        obj14.update({pdf.PdfName("DocMDP"): obj12ref})
        obj15 = pdf.PdfDict()
        obj15.update(
            {
                pdf.PdfName("Fields"): pdf.PdfArray([obj13ref]),
                pdf.PdfName("SigFlags"): PdfNumber(3),
            }
        )
        obj15ref = self.addObject(obj15)
        if self.annotbutton:
            from pdf_annotate.annotations.image import Image
            from pdf_annotate.annotations.text import FreeText
            from pdf_annotate.config.appearance import Appearance
            from pdf_annotate.config.location import Location
            from pdf_annotate.util.geometry import identity

            annotation = "User signature text"
            x1, y1, x2, y2 = (470, 0, 570, 100)
            annotation = FreeText(
                Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0),
                Appearance(
                    fill=[0, 0, 0],
                    stroke_width=1,
                    wrap_text=True,
                    font_size=12,
                    content=annotation,
                ),
            )
            pdfa = annotation.as_pdf_object(identity(), page=None)
            objapn = self.extend(pdfa[pdf.PdfName("AP")][pdf.PdfName("N")])
            objapnref = self.addObject(objapn)
            for name in (
                "BS",
                "C",
                "Contents",
                "DA",
                "Rect",
                # "Subtype",
            ):
                key = pdf.PdfName(name)
                v = pdfa[key]
                if isinstance(v, str):
                    v = v.replace("/", "//")
                    v = pdf.PdfString.from_unicode(v)
                elif isinstance(v, list):
                    v = pdf.PdfArray(v)
                obj13.update({key: v})

            objap = pdf.PdfDict()
            objap.update({pdf.PdfName("N"): objapnref})
            obj13.update(
                {
                    pdf.PdfName("SM"): pdf.PdfString.from_unicode("TabletPOSinline"),
                    pdf.PdfName("AP"): objap,
                }
            )
            self.objects[root.Pages.Kids[0].indirect[0] - 1] = page0
            annots = pdf.PdfArray([obj13ref])
            # if False and pdf.PdfName("Annots") in page0:
            if pdf.PdfName("Annots") in page0:
                page0annots = page0[pdf.PdfName("Annots")]
                if isinstance(page0annots, PdfIndirect):
                    annots.insert(0, page0annots)
                elif isinstance(page0annots, pdf.PdfArray):
                    annots = page0annots
                    annots.append(obj13ref)
            page0.update({pdf.PdfName("Annots"): annots})

        croot = self.copydict(root)
        croot.update(
            {pdf.PdfName("Perms"): obj14ref, pdf.PdfName("AcroForm"): obj15ref}
        )
        self.objects[root.indirect[0] - 1] = croot
        try:
            ID = self.prev.ID[0]
        except:
            b = hashlib.md5(self.datau).digest()
            ID = pdf.PdfString.from_bytes(b, bytes_encoding="hex")
        b = repr(random.random()).encode()
        b = hashlib.md5(b).digest()
        self.trailer = pdf.PdfDict(
            Size=len(self.objects),
            Root=PdfIndirect(root.indirect),
            Info=PdfIndirect(self.prev.Info.indirect),
            Prev=self.startprev,
            ID=pdf.PdfArray([ID, pdf.PdfString.from_bytes(b, bytes_encoding="hex")]),
        )
        if self.prev.private.pdfdict.encrypt:
            self.trailer.Encrypt = PdfIndirect(
                self.prev.private.pdfdict.encrypt.indirect
            )

    def sign(self, md, algomd):
        tspurl = "http://public-qlts.certum.pl/qts-17"
        tspurl = None
        fname = "demo2_user1.p12"
        with open(fname, "rb") as fp:
            p12 = pkcs12.load_key_and_certificates(
                fp.read(), b"1234", backends.default_backend()
            )
        contents = signer.sign(
            None, p12[0], p12[1], p12[2], algomd, True, md, None, False, tspurl
        )
        return contents

    def main(self):
        algomd = "sha1"
        aligned = False

        if aligned:
            zeros = b"0" * 0x4000
        else:
            md = getattr(hashlib, algomd)().digest()
            zeros = self.sign(md, algomd)
            zeros = zeros.hex().encode()

        self.makepdf(zeros)

        fo = io.BytesIO()
        self.write(fo)
        datas = fo.getvalue()

        br = [0, 0, 0, 0]
        bfrom = (" ".join([PdfNumberB.Format] * 4)) % tuple(br)
        bfrom = ("[" + bfrom + "]").encode()

        pdfbr1 = datas.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = [
            0,
            self.startdata + pdfbr1 - 1,
            self.startdata + pdfbr2 + 1,
            len(datas) - pdfbr2 - 1,
        ]
        bto = b"[%d %d %d %d]" % tuple(br)
        bto += b" " * (len(bfrom) - len(bto))
        assert len(bfrom) == len(bto)
        datas = datas.replace(bfrom, bto, 1)

        md = getattr(hashlib, algomd)()
        md.update(self.datau)
        b1 = datas[: br[1] - self.startdata]
        b2 = datas[br[2] - self.startdata :]
        md.update(b1)
        md.update(b2)
        md = md.digest()

        contents = self.sign(md, algomd)
        contents = contents.hex().encode("utf-8")
        if aligned:
            nb = len(zeros) - len(contents)
            contents += b"0" * nb
        datas = datas.replace(zeros, contents, 1)

        fname = self.fname.replace(".pdf", "-signed-pdfrw.pdf")
        with open(fname, "wb") as fp:
            fp.write(self.datau)
            fp.write(datas)


def main():
    if len(sys.argv) > 2:
        cls = Signer(sys.argv[1], sys.argv[2])
        cls.main()
    else:
        for fname, password in (
            ("pdf.pdf", ""),
            # ("pdf-encrypted.pdf", "1234"),
            # ("pdf-buggy.pdf", ""),
        ):
            cls = Signer(fname, password)
            cls.main()


main()
