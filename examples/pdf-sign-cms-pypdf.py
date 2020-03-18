#!/usr/bin/env vpython3
import sys
import io
import hashlib
import codecs
import struct
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive.pdf.PyPDF2 import pdf, generic as po
from endesive import signer


def S(s):
    return po.createStringObject(codecs.BOM_UTF16_BE + s.encode("utf-16be"))


class B(po.utils.bytes_type, po.PdfObject):
    original_bytes = property(lambda self: self)

    def writeToStream(self, stream, encryption_key):
        stream.write(b"<")
        stream.write(self)
        stream.write(b">")


class WNumberObject(po.NumberObject):
    Format = "%010d"


class Main(pdf.PdfFileWriter):
    def write(self, stream, prev, startxref):

        externalReferenceMap = {}

        # PDF objects sometimes have circular references to their /Page objects
        # inside their object tree (for example, annotations).  Those will be
        # indirect references to objects that we've recreated in this PDF.  To
        # address this problem, PageObject's store their original object
        # reference number, and we add it to the external reference map before
        # we sweep for indirect references.  This forces self-page-referencing
        # trees to reference the correct new object location, rather than
        # copying in a new copy of the page object.
        for objIndex in range(len(self._objects)):
            obj = self._objects[objIndex]
            if isinstance(obj, pdf.PageObject) and obj.indirectRef != None:
                data = obj.indirectRef
                if data.pdf not in externalReferenceMap:
                    externalReferenceMap[data.pdf] = {}
                if data.generation not in externalReferenceMap[data.pdf]:
                    externalReferenceMap[data.pdf][data.generation] = {}
                externalReferenceMap[data.pdf][data.generation][
                    data.idnum
                ] = po.IndirectObject(objIndex + 1, 0, self)

        self.stack = []
        self._sweepIndirectReferences(externalReferenceMap, self._root)
        del self.stack

        # Begin writing:
        positions = {}
        for i in range(2, len(self._objects)):
            idnum = i + 1
            obj = self._objects[i]
            if obj is None:
                continue
            positions[idnum] = startxref + stream.tell()
            stream.write(pdf.b_(str(idnum) + " 0 obj\n"))
            key = None
            if hasattr(self, "_encrypt") and idnum != self._encrypt.idnum:
                pack1 = struct.pack("<i", i + 1)[:3]
                pack2 = struct.pack("<i", 0)[:2]
                key = self._encrypt_key + pack1 + pack2
                assert len(key) == (len(self._encrypt_key) + 5)
                md5_hash = hashlib.md5(key).digest()
                key = md5_hash[: min(16, len(self._encrypt_key) + 5)]
            obj.writeToStream(stream, key)
            stream.write(pdf.b_("\nendobj\n"))

        # xref table
        xref_location = startxref + stream.tell()
        stream.write(pdf.b_("xref\n"))
        stream.write(pdf.b_("0 1\n"))
        stream.write(pdf.b_("0000000000 65535 f\n"))
        stream.write(pdf.b_("9 %d\n" % (len(positions))))
        for key in sorted(positions.keys()):
            stream.write(pdf.b_("%010d %05d n\n" % (positions[key], 0)))

        # trailer
        stream.write(pdf.b_("trailer\n"))
        trailer = po.DictionaryObject()
        trailer.update(
            {
                po.NameObject("/Size"): po.NumberObject(len(self._objects) + 1),
                po.NameObject("/Root"): self.x_root,
                po.NameObject("/Info"): self.x_info,
                po.NameObject("/Prev"): po.NumberObject(prev.startxref),
            }
        )
        if hasattr(self, "_ID"):
            trailer[po.NameObject("/ID")] = self._ID
        if hasattr(self, "_encrypt"):
            trailer[po.NameObject("/Encrypt")] = self._encrypt
        trailer.writeToStream(stream, None)

        # eof
        stream.write(pdf.b_("\nstartxref\n%s\n%%%%EOF\n" % (xref_location)))

    def makepdf(self, prev, zeros):
        catalog = prev.trailer["/Root"]
        pages = catalog["/Pages"].getObject()
        page0 = pages["/Kids"][0]
        pages = catalog.raw_get("/Pages")

        self.x_info = prev.trailer.raw_get("/Info")
        self.x_root = prev.trailer.raw_get("/Root")

        while len(self._objects) < self.x_root.idnum:
            self._objects.append(None)
        # 14
        obj = po.DictionaryObject()
        obj.update(
            {
                po.NameObject("/Type"): po.NameObject("/TransformParams"),
                po.NameObject("/P"): po.NumberObject(2),
                po.NameObject("/V"): po.NameObject("/1.2"),
            }
        )
        obj14 = self._addObject(obj)
        # 13
        obj = po.DictionaryObject()
        obj.update(
            {
                po.NameObject("/Type"): po.NameObject("/SigRef"),
                po.NameObject("/TransformMethod"): po.NameObject("/DocMDP"),
                po.NameObject("/DigestMethod"): po.NameObject("/SHA256"),
                po.NameObject("/TransformParams"): obj14,
            }
        )
        obj13 = self._addObject(obj)
        # 12
        obj = po.DictionaryObject()
        obj.update(
            {
                po.NameObject("/Type"): po.NameObject("/Sig"),
                po.NameObject("/Filter"): po.NameObject("/Adobe.PPKLite"),
                po.NameObject("/SubFilter"): po.NameObject("/adbe.pkcs7.detached"),
                po.NameObject("/Name"): S("Grzegorz Makarewicz"),
                po.NameObject("/Location"): S("Szczecin"),
                po.NameObject("/Reason"): S("Dokument podpisany cyfrowo"),
                po.NameObject("/M"): S("D:20200314100055+00'00'"),
                po.NameObject("/Reference"): po.ArrayObject([obj13]),
                po.NameObject("/Contents"): B(zeros),
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
        obj12 = self._addObject(obj)
        # 10
        obj = po.DictionaryObject()
        obj.update({po.NameObject("/DocMDP"): obj12})
        obj10 = self._addObject(obj)
        # 11
        obj = po.DictionaryObject()
        obj.update(
            {
                po.NameObject("/FT"): po.NameObject("/Sig"),
                po.NameObject("/Type"): po.NameObject("/Annot"),
                po.NameObject("/Subtype"): po.NameObject("/Widget"),
                po.NameObject("/F"): po.NumberObject(132),
                po.NameObject("/T"): S("Signature1"),
                po.NameObject("/V"): obj12,
                po.NameObject("/P"): page0,
                po.NameObject("/Rect"): po.ArrayObject(
                    [
                        po.NumberObject(0),
                        po.NumberObject(0),
                        po.NumberObject(0),
                        po.NumberObject(0),
                    ]
                ),
            }
        )
        obj11 = self._addObject(obj)
        # 9
        form = po.DictionaryObject()
        form.update(
            {
                po.NameObject("/Fields"): po.ArrayObject([obj11]),
                po.NameObject("/SigFlags"): po.NumberObject(3),
            }
        )
        obj = catalog
        obj.update({po.NameObject("/Perms"): obj10, po.NameObject("/AcroForm"): form})
        self._objects[self.x_root.idnum - 1] = obj
        self.x_root = po.IndirectObject(self.x_root.idnum, 0, self)

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
        algomd = "sha256"

        md = getattr(hashlib, algomd)().digest()
        contents = self.sign(md, algomd)
        zeros = contents.hex().encode("utf-8")

        with open(fname, "rb") as fi:
            datau = fi.read()
        startxref = len(datau)

        fi = io.BytesIO(datau)

        prev = pdf.PdfFileReader(fi)
        if prev.isEncrypted:
            prev.decrypt(password)
        self.makepdf(prev, zeros)
        if prev.isEncrypted:
            self.encrypt(password)

        fo = io.BytesIO()
        self.write(fo, prev, startxref)
        datas = fo.getvalue()

        pdfbr1 = datas.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)

        bfmt = b"[ %010d %010d %010d %010d ]"
        br = [0, 0, 0, 0]
        bfrom = bfmt % tuple(br)

        br = [0, startxref + pdfbr1 - 1, startxref + pdfbr2 + 1, len(datas) - pdfbr2 - 1]
        bto = bfmt % tuple(br)
        datas = datas.replace(bfrom, bto, 1)

        md = getattr(hashlib, algomd)()
        md.update(datau)
        b1 = datas[:br[1] - startxref]
        b2 = datas[br[2] - startxref:]
        md.update(b1)
        md.update(b2)
        md = md.digest()

        contents = self.sign(md, algomd)
        contents = contents.hex().encode("utf-8")

        datas = datas.replace(zeros, contents, 1)

        fname = fname.replace('.pdf', '-signed-pypdf.pdf')
        with open(fname, "wb") as fp:
            fp.write(datau)
            fp.write(datas)

def main():
    cls = Main()
    cls.main("pdf.pdf", "")

    cls = Main()
    cls.main("pdf-encrypted.pdf", "1234")

main()
