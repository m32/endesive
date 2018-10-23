# *-* coding: utf-8 *-*
import hashlib
from io import BytesIO

from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjRef

from endesive import signer


class SignedData(object):

    def aligned(self, data):
        data = b''.join([b'%02x' % i for i in data])
        nb = 0x4000 - len(data)
        data = data + b'0' * (0x4000 - len(data))
        return data

    def getdata(self, pdfdata1, objid, startxref, document):
        i0 = None
        for xref in document.xrefs:
            try:
                (strmid, index, genno) = xref.get_pos(objid)
            except KeyError:
                continue
            i0 = index
            break
        i1 = startxref
        for xref in document.xrefs:
            for (_, offset, _) in xref.offsets.values():
                if offset > i0:
                    i1 = min(i1, offset)
        data = pdfdata1[i0:i1]
        i0 = data.find(b'<<') + 2
        i1 = data.rfind(b'>>')
        data = data[i0:i1]
        return data

    def makeobj(self, no, data):
        return (b'%d 0 obj\n<<' % no) + data + b'>>\nendobj\n'

    def makepdf(self, pdfdata1, udct, zeros):
        parser = PDFParser(BytesIO(pdfdata1))
        document = PDFDocument(parser, fallback=False)

        prev = document.find_xref(parser)
        info = document.xrefs[0].trailer['Info'].objid
        root = document.xrefs[0].trailer['Root'].objid
        size = document.xrefs[0].trailer['Size']
        page = document.getobj(document.catalog['Pages'].objid)['Kids'][0].objid

        infodata = self.getdata(pdfdata1, info, prev, document).strip()
        rootdata = self.getdata(pdfdata1, root, prev, document).strip()
        pagedata = self.getdata(pdfdata1, page, prev, document).strip()

        no = size
        objs = [
            self.makeobj(page, (b'/Annots[%d 0 R]' % (no + 3)) + pagedata),
            self.makeobj(no + 0, infodata),
            self.makeobj(no + 1, (b'/AcroForm %d 0 R' % (no + 2)) + rootdata),
            self.makeobj(no + 2, b'/Fields[%d 0 R]/SigFlags %d' % (no + 3, udct[b'sigflags'])),
            self.makeobj(no + 3,
                         b'/AP<</N %d 0 R>>/F 132/FT/Sig/P %d 0 R/Rect[0 0 0 0]/Subtype/Widget/T(Signature1)/V %d 0 R' % (
                         no + 4, page, no + 5)),
            self.makeobj(no + 4, b'/BBox[0 0 0 0]/Filter/FlateDecode/Length 8/Subtype/Form/Type/XObject'),
            b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
            self.makeobj(no + 5, (b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/ContactInfo(%s)\
/Filter/Adobe.PPKLite/Location(%s)/M(D:%s)/Prop_Build<</App<</Name/>>>>/Reason(%s)/SubFilter/adbe.pkcs7.detached/Type/Sig\
/Contents <' % (udct[b'contact'], udct[b'location'], udct[b'signingdate'], udct[b'reason'])) + zeros + b'>'),
        ]

        pdfdata2 = b''.join(objs)
        xref = b'''\
xref\n\
%(page)d 1\n\
%(p0)010d 00000 n \n\
%(no)d 6\n\
%(n0)010d 00000 n \n\
%(n1)010d 00000 n \n\
%(n2)010d 00000 n \n\
%(n3)010d 00000 n \n\
%(n4)010d 00000 n \n\
%(n5)010d 00000 n \n\
'''
        startxref = len(pdfdata1)
        dct = {
            b'page': page,
            b'no': no,
            b'startxref': startxref + len(pdfdata2),
            b'prev': prev,
            b'info': no + 0,
            b'root': no + 1,
            b'size': 6,
            b'p0': startxref + pdfdata2.find(b'\n%d 0 obj\n' % page) + 1,
            b'n0': startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + 0)) + 1,
            b'n1': startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + 1)) + 1,
            b'n2': startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + 2)) + 1,
            b'n3': startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + 3)) + 1,
            b'n4': startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + 4)) + 1,
            b'n5': startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + 5)) + 1,
        }

        trailer = b'''\
trailer
<</ID [<1><2>]/Info %(info)d 0 R/Prev %(prev)d/Root %(root)d 0 R/Size %(size)d>>\n\
startxref\n\
%(startxref)d\n\
%%%%EOF\n\
'''

        xref = xref % dct
        trailer = trailer % dct

        pdfdata2 = pdfdata2 + xref + trailer

        return pdfdata2

    def sign(self, datau, dct, key, cert, othercerts, algomd):
        zeros = self.aligned(b'\0')

        pdfdata2 = self.makepdf(datau, dct, zeros)

        startxref = len(datau)
        pdfbr1 = pdfdata2.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = [0, startxref + pdfbr1 - 1, startxref + pdfbr2 + 1, len(pdfdata2) - pdfbr2 - 1]
        brfrom = b'[0000000000 0000000000 0000000000 0000000000]'
        brto = b'[%010d %010d %010d %010d]' % tuple(br)
        pdfdata2 = pdfdata2.replace(brfrom, brto, 1)

        md = getattr(hashlib, algomd)()
        md.update(datau)
        b1 = pdfdata2[:br[1] - startxref]
        b2 = pdfdata2[br[2] - startxref:]
        md.update(b1)
        md.update(b2)
        md = md.digest()

        contents = signer.sign(None, key, cert, othercerts, algomd, True, md)
        contents = self.aligned(contents)
        pdfdata2 = pdfdata2.replace(zeros, contents, 1)

        return pdfdata2


def sign(datau, udct, key, cert, othercerts, algomd):
    cls = SignedData()
    return cls.sign(datau, udct, key, cert, othercerts, algomd)
