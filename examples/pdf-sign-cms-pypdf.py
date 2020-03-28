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
    Format = "%08d"


class Main(pdf.PdfFileWriter):
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

        # self._objects[0] = pages catalog
        # self._objects[1] = producer info
        # Begin writing:
        stream.write(pdf.b_("\r\n"))
        positions = {}
        for i in range(2, len(self._objects)):
            idnum = i + 1
            obj = self._objects[i]
            if obj is None:
                positions[idnum] = 0
                continue
            positions[idnum] = startxref + stream.tell()
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

        # xref table
        xref_location = startxref + stream.tell()
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
        trailer = po.DictionaryObject()
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
        trailer.writeToStream(stream, None)

        # eof
        stream.write(pdf.b_("\nstartxref\n%s\n%%%%EOF\n" % (xref_location)))

    def makepdf(self, prev, zeros):
        catalog = prev.trailer["/Root"]
        size = prev.trailer["/Size"]
        pages = catalog["/Pages"].getObject()
        page0 = pages["/Kids"][0]
        pages = catalog.raw_get("/Pages")

        self.x_info = prev.trailer.raw_get("/Info")
        self.x_root = prev.trailer.raw_get("/Root")

        while len(self._objects) < size - 1:
            self._objects.append(None)

        obj14 = po.DictionaryObject()
        obj14ref = self._addObject(obj14)
        obj13 = po.DictionaryObject()
        obj13ref = self._addObject(obj13)
        obj12 = po.DictionaryObject()
        obj12ref = self._addObject(obj12)
        obj11 = po.DictionaryObject()
        obj11ref = self._addObject(obj11)
        obj10 = po.DictionaryObject()
        obj10ref = self._addObject(obj10)

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
                po.NameObject("/DigestMethod"): po.NameObject("/SHA1"),
                po.NameObject("/TransformParams"): obj10ref,
            }
        )
        obj12.update(
            {
                po.NameObject("/Type"): po.NameObject("/Sig"),
                po.NameObject("/Filter"): po.NameObject("/Adobe.PPKLite"),
                po.NameObject("/SubFilter"): po.NameObject("/adbe.pkcs7.detached"),
                po.NameObject("/Name"): S("Example User"),
                po.NameObject("/Location"): S("Los Angeles, CA"),
                po.NameObject("/Reason"): S("Testing"),
                po.NameObject("/M"): S("D:20200317214832+01'00'"),
                po.NameObject("/Reference"): po.ArrayObject([obj11ref]),
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
        obj13.update(
            {
                po.NameObject("/FT"): po.NameObject("/Sig"),
                po.NameObject("/Type"): po.NameObject("/Annot"),
                po.NameObject("/Subtype"): po.NameObject("/Widget"),
                po.NameObject("/F"): po.NumberObject(132),
                po.NameObject("/T"): S("Signature1"),
                po.NameObject("/V"): obj12ref,
                po.NameObject("/P"): page0,
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
        obj = po.DictionaryObject()
        obj.update(
            {
                po.NameObject("/Fields"): po.ArrayObject([obj13ref]),
                po.NameObject("/SigFlags"): po.NumberObject(3),
            }
        )
        catalog.update(
            {po.NameObject("/Perms"): obj14ref, po.NameObject("/AcroForm"): obj}
        )
        self._objects[self.x_root.idnum - 1] = catalog
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
        algomd = "sha1"
        aligned = False

        if aligned:
            zeros = b"0" * 37888
        else:
            md = getattr(hashlib, algomd)().digest()
            contents = self.sign(md, algomd)
            zeros = contents.hex().encode("utf-8")

        with open(fname, "rb") as fi:
            datau = fi.read()
        startxref = len(datau)

        fi = io.BytesIO(datau)

        prev = pdf.PdfFileReader(fi)
        if prev.isEncrypted:
            rc = prev.decrypt(password)
        else:
            rc = 0
        self.makepdf(prev, zeros)
        if prev.isEncrypted:
            self.encrypt(prev, password, rc)
        else:
            self._encrypt_key = None
        self._ID = po.ArrayObject(
            [
                prev.trailer["/ID"][0],
                # po.ByteStringObject(hashlib.md5(pdf.b_(repr(time.time()))).digest()),
                po.ByteStringObject(
                    hashlib.md5(pdf.b_(repr(random.random()))).digest()
                ),
            ]
        )

        fo = io.BytesIO()
        self.write(fo, prev, startxref)
        datas = fo.getvalue()

        br = [0, 0, 0, 0]
        bfrom = b"[%08d %08d %08d %08d]" % tuple(br)

        pdfbr1 = datas.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = [
            0,
            startxref + pdfbr1 - 1,
            startxref + pdfbr2 + 1,
            len(datas) - pdfbr2 - 1,
        ]
        bto = b"[%d %d %d %d]" % tuple(br)
        bto += b" " * (len(bfrom) - len(bto))
        assert len(bfrom) == len(bto)
        datas = datas.replace(bfrom, bto, 1)

        md = getattr(hashlib, algomd)()
        md.update(datau)
        b1 = datas[: br[1] - startxref]
        b2 = datas[br[2] - startxref :]
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
    if 0:
        cls = Main()
        cls.main(sys.argv[1], "")
    if 1:
        cls = Main()
        cls.main("pdf.pdf", "")

        cls = Main()
        cls.main("pdf-encrypted.pdf", "1234")


main()
