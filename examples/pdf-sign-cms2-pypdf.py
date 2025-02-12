#!/usr/bin/env vpython3
#
# use pypdf instead of unmaintained local copy
#
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

from pypdf import PdfReader, PdfWriter, generic as po

class UnencryptedBytes(po.ByteStringObject):

    def write_to_stream(self, stream, encryption_key = None):
        stream.write(b"<")
        stream.write(self)
        stream.write(b">")


class WNumberObject(po.NumberObject):
    Format = b"%08d"

    def write_to_stream(self, stream, encryption_key = None):
        stream.write(self.Format % self)

class Signer(PdfWriter):
    def __init__(self, fileobj, *args, **kwargs):
        super().__init__(fileobj=fileobj, *args, **kwargs, incremental=True)

    # method written from scratch because binary/compressed xref
    # created by pypdf makes it impossible to check the signature
    # in acrobat reader
    def _write_increment(self, stream):
        from pypdf.constants import TrailerKeys as TK
        object_positions = []
        # write new and updated objects
        original_hash_count = len(self._original_hash)
        for i, obj in enumerate(self._objects):
            if obj is not None and (
                i >= original_hash_count
                or obj.hash_bin() != self._original_hash[i]
            ):
                idnum = i + 1
                assert isinstance(obj, po.PdfObject)  # mypy
                object_positions.append(stream.tell())
                stream.write(f"{idnum} 0 obj\n".encode())
                """ encryption is not operational
                if self._encryption and obj != self._encrypt_entry:
                    obj = self._encryption.encrypt_object(obj, idnum, 0)
                """
                obj.write_to_stream(stream)
                stream.write(b"\nendobj\n")
            else:
                object_positions.append(0)

        # save xref location for use in trailer
        xref_location = stream.tell()

        # write new xref table
        stream.write(b"xref\n")
        # first object is allways the same: 0 0xffff f
        stream.write(f"0 1\n".encode())
        stream.write(f"{0:0>10} {65535:0>5} f \n".encode())
        i = 0
        while i < len(object_positions):
            while i < len(object_positions) and not object_positions[i]:
                i += 1
            if i == len(object_positions):
                break
            active = i # number of continious elements
            while active < len(object_positions) and object_positions[active]:
                active += 1
            stream.write(f"{i+1} {active-i}\n".encode())
            while i < len(object_positions) and object_positions[i]:
                stream.write(f"{object_positions[i]:0>10} {0:0>5} n \n".encode())
                i += 1

        # create new ID
        self.generate_file_identifiers()
        # prepare new trailer
        trailer = po.DictionaryObject(
            {
                po.NameObject(TK.SIZE): po.NumberObject(len(self._objects) + 1),
                po.NameObject(TK.ROOT): self.root_object.indirect_reference,
                po.NameObject(TK.PREV): po.NumberObject(self._reader._startxref),
                po.NameObject(TK.ID): self._ID,
            }
        )
        if self._info is not None:
            trailer[po.NameObject(TK.INFO)] = self._info.indirect_reference
        if self._encrypt_entry:
            trailer[po.NameObject(TK.ENCRYPT)] = self._encrypt_entry.indirect_reference
        stream.write(b"trailer\n")
        trailer.write_to_stream(stream)
        stream.write(f"\nstartxref\n{xref_location}\n%%EOF\n".encode())  # eof

    def makepdf(self, algomd, zeros):
        page0ref = self.get_page(0).indirect_reference

        obj13 = po.DictionaryObject()
        obj13ref = self._add_object(obj13)
        obj12 = po.DictionaryObject()
        obj12ref = self._add_object(obj12)
        obj12.update(
            {
                po.NameObject("/Type"): po.NameObject("/Sig"),
                po.NameObject("/Filter"): po.NameObject("/Adobe.PPKLite"),
                po.NameObject("/SubFilter"): po.NameObject("/adbe.pkcs7.detached"),
                po.NameObject("/Name"): po.TextStringObject("Example User"),
                po.NameObject("/Location"): po.TextStringObject("Los Angeles, CA"),
                po.NameObject("/Reason"): po.TextStringObject("Testing"),
                po.NameObject("/M"): po.TextStringObject("D:20200317214832+01'00'"),
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
                po.NameObject("/T"): po.TextStringObject("Signature1"),
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

        if "/AcroForm" in self._root_object:
            formref = self._root_object.raw_get("/AcroForm")
            form = formref.get_object()
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
            form.indirect_reference = formref.idnum
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
            formref = self._add_object(form)
            self._root_object[po.NameObject("/AcroForm")] = formref

        if 0 and "/Perms" not in self._root_object:
            obj10 = po.DictionaryObject()
            obj10ref = self._add_object(obj10)
            obj11 = po.DictionaryObject()
            obj11ref = self._add_object(obj11)
            obj14 = po.DictionaryObject()
            obj14ref = self._add_object(obj14)
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
            self._root_object[po.NameObject("/Perms")] = obj14ref

    def sign(self, md, algomd):
        tspurl = "http://public-qlts.certum.pl/qts-17"
        tspurl = None
        pk12fname = "ca/demo2_user1.p12"
        pk12pass = b"1234"
        pk12fname = "/home/mak/Dokumenty/m32/ssl/actalis/actalis.p12"
        pk12fname = "/home/mak/Dokumenty/m32/ssl/unizeto/unizeto.p12"
        pk12pass = sys.argv[1].encode()
        with open(pk12fname, "rb") as fp:
            p12 = pkcs12.load_key_and_certificates(
                fp.read(), pk12pass, backends.default_backend()
            )
        contents = signer.sign(
            None, p12[0], p12[1], p12[2], algomd, True, md, None, False, tspurl
        )
        return contents

    def main(self, algomd="sha256", aligned=False):
        if aligned:
            zeros = b"0" * 32768
        else:
            md = getattr(hashlib, algomd)().digest()
            contents = self.sign(md, algomd)
            zeros = b"00" * len(contents)

        self.makepdf(algomd, zeros)

        fo = io.BytesIO()
        self.write(fo)
        datas = fo.getvalue()

        br = [0, 0, 0, 0]
        bfrom = (b"[ " + b" ".join([WNumberObject.Format] * 4) + b" ]") % tuple(br)

        pdfbr1 = datas.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = [
            0,
            pdfbr1 - 1,
            pdfbr2 + 1,
            len(datas) - pdfbr2 - 1,
        ]
        bto = b"[%d %d %d %d]" % tuple(br)
        bto += b" " * (len(bfrom) - len(bto))
        assert len(bfrom) == len(bto)
        datas = datas.replace(bfrom, bto, 1)

        md = getattr(hashlib, algomd)()
        md.update(datas[: br[1]])
        md.update(datas[br[2] :])
        md = md.digest()

        contents = self.sign(md, algomd)
        contents = contents.hex().encode("utf-8")
        if aligned:
            nb = len(zeros) - len(contents)
            if nb > 0:
                contents += b"0" * nb
        datas = datas.replace(zeros, contents, 1)

        return datas


def main():
    from pypdf.annotations import Text
    fname = "pdf.pdf"

    print('*'*20, '1')
    writer = Signer(fname)
    datas = writer.main()
    fname = "pdf-signed-cms2-pypdf-1.pdf"
    with open(fname, "wb") as fp:
        fp.write(datas)

    if 0:
        print('*'*20, '2')
        writer = Signer(fname)
        text_annotation = Text(
            text="Hello World\nThis is incremental pdf with annotation!",
            rect=(150, 550, 500, 650),
            open=True,
        )
        #page = writer.get_page(0)
        page = writer.pages[1]
        writer.add_annotation(page, annotation=text_annotation)
        datas = writer.main()
        fname = "pdf-signed-cms2-pypdf-2.pdf"
        with open(fname, "wb") as fp:
            fp.write(datas)

main()
