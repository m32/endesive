# *-* coding: utf-8 *-*
import sys
import operator
import hashlib
import re
from io import BytesIO

from pdfminer.pdfdocument import PDFDocument, PDFXRefStream
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjRef
from pdfminer.psparser import PSKeyword, PSLiteral
from pdfminer.utils import isnumber

from pdf_annotate.annotations.image import Image
from pdf_annotate.annotations.text import FreeText
from pdf_annotate.config.appearance import Appearance
from pdf_annotate.config.location import Location
from pdf_annotate.util.geometry import identity

from endesive import signer

ESC_PAT = re.compile(r'[\000-\037&<>()"\042\047\134\177-\377]')


def e(s):
    return ESC_PAT.sub(lambda m: '&#%d;' % ord(m.group(0)), s)


class SignedData(object):

    def aligned(self, data):
        if sys.version[0] < '3':
            data = data.encode('hex').encode('utf-8')
        else:
            data = data.hex().encode('utf-8')
        nb = 0x4000 - len(data)
        data = data + b'0' * (0x4000 - len(data))
        return data

    def dumpobj(self, out, obj):
        if obj is None:
            out.write(b'null ')
            return

        if isinstance(obj, dict):
            out.write(b'<<')
            for (k, v) in obj.items():
                if sys.version[0] < '3':
                    out.write(b'/%s ' % k)
                else:
                    out.write(b'/%s ' % bytes(k, 'utf-8'))
                self.dumpobj(out, v)
            out.write(b'>>')
            return

        if isinstance(obj, list):
            out.write(b'[')
            for v in obj:
                self.dumpobj(out, v)
            out.write(b']')
            return

        if isinstance(obj, bytes):
            out.write(b'(')
            out.write(obj)
            out.write(b')')
            return

        if isinstance(obj, str):
            out.write(b'(')
            out.write(bytes(e(obj), 'utf-8'))
            out.write(b')')
            return

        if isinstance(obj, bool):
            if obj:
                out.write(b'true ')
            else:
                out.write(b'false ')
            return
        if isnumber(obj):
            if isinstance(obj, float):
                s = (b'%.5f ' % obj).rstrip(b'0')
            else:
                s = b'%d ' % obj
            out.write(s)
            return

        if isinstance(obj, PDFObjRef):
            out.write(b'%d 0 R ' % (obj.objid))
            return

        if isinstance(obj, PSKeyword):
            if sys.version[0] < '3':
                out.write(b'/%s ' % obj.name)
            else:
                out.write(b'/%s ' % bytes(obj.name, 'utf-8'))
            return

        if isinstance(obj, PSLiteral):
            if sys.version[0] < '3':
                out.write(b'/%s ' % obj.name)
            else:
                out.write(b'/%s ' % bytes(obj.name, 'utf-8'))
            return

        # if isinstance(obj, PDFStream):
        raise TypeError(obj)

    def getdata(self, pdfdata1, objid, startxref, document, remove=None):
        obj = document.getobj(objid)
        for elem in remove or ():
            try:
                del obj[elem]
            except KeyError as e:
                pass
        fp = BytesIO()
        self.dumpobj(fp, obj)
        data = fp.getvalue().strip()
        return data[2:-2].strip()

    def makeobj(self, no, data, datas=b''):
        return (b'%d 0 obj\n<<' % no) + data + b'>>\n' + datas + b'endobj\n'

    def getfields(self, root, document):
        obj = document.getobj(root)
        try:
            obj = obj['AcroForm']
            obj = document.getobj(obj.objid)
            sigflags = obj['SigFlags']
            fields = obj['Fields']
        except KeyError as e:
            return 1, b''
        fp = BytesIO()
        self.dumpobj(fp, fields)
        data = fp.getvalue().strip()[1:-1]
        return len(fields)+1, data

    def getannots(self, root, document):
        obj = document.getobj(root)
        try:
            annots = obj['Annots']
        except KeyError as e:
            return b''
        fp = BytesIO()
        self.dumpobj(fp, annots)
        data = fp.getvalue().strip()[1:-1]
        return data

    def makeannotation(self, obj, nobj):
        obj_list = []
        result = b'%d 0 obj\n<<' % nobj
        for key, value in obj.items():
            if isinstance(value, str):
                value = value.encode('latin1')
            elif isinstance(value, bytes):
                value = value
            elif isinstance(value, (int, float)):
                value = str(value).encode('latin1')
            elif isinstance(value, list):
                value = b'[%s]' % b' '.join([str(n).encode('latin1') for n in value])
            elif isinstance(value, dict):
                nobj += 1
                value, d = b'%d 0 R' % nobj, value
                fr, nobj = self.makeannotation(d, nobj)
                obj_list.append(fr)
            else:
                continue
            result += b'%s %s ' % (key.encode('latin1'), value)
        result += b'>>\n'
        stream = obj.stream
        if stream is not None:
            result += b'stream\n%s\nendstream\n' % stream.encode('latin1')
        result += b'endobj\n'
        result += b''.join(obj_list)
        return result, nobj

    def textvisual(self, no, udct, nsig, page):
        annotation = udct.get(b'signature', b'').decode('utf8')
        x1, y1, x2, y2 = udct.get(b'signaturebox', (0, 0, 0, 0))
        annotation = FreeText(
            Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0),
            Appearance(
                fill=[0, 0, 0],
                stroke_width=1,
                wrap_text=True,
                font_size=udct.get(b'fontsize', 12),
                content=annotation,
            ),
        )
        pdfa = annotation.as_pdf_object(identity(), page=None)
        pdfar = b'[%d %d %d %d]' % tuple(pdfa.Rect)
        pdfao = pdfa.AP.N
        visual, nav = self.makeannotation(pdfao, no+4)
        obj = [
            self.makeobj(no + 3,
                         b'''
/Type
/Annot
/Subtype
%s
/AP <</N %d 0 R>>
/BS <</S /S /Type /Border /W 0>>
/C []
/Contents (%s)
/DA (0 0 0 rg /%s 12 Tf)
/Rect %s
/F 704
/P %d 0 R
/FT
/Sig
%s
/T(Signature%d)
/V %d 0 R
''' % (
                             b'/Widget' if udct.get(b'sigbutton', False) else b'/FreeText',
                             no + 4, pdfa.Contents.encode('latin1'),
                             pdfa.AP.N.Resources.Font.keys()[0].encode('latin1'),
                             pdfar,
                             page,
                             b'/SM(TabletPOSinline)' if udct.get(b'sigbutton', False) else b'',
                             nsig, nav + 1)),

            visual
        ]
        return b''.join(obj), nav

    def imagevisual(self, image_path, no, udct, nsig, page):
        x1, y1, x2, y2 = udct.get(b'signaturebox', (0, 0, 0, 0))
        annotation = Image(
            Location(x1=x1, y1=y1, x2=x2, y2=y2, page=0),
            Appearance(image=image_path),
        )

        pdfa = annotation.as_pdf_object(identity(), page=None)
        pdfar = b'[%d %d %d %d]' % tuple(pdfa.Rect)
        pdfao = pdfa.AP.N
        visual, nav = self.makeannotation(pdfao, no+4)
        obj = [
            self.makeobj(no + 3,
                         b'''
/Type
/Annot
/Subtype %s
/Rect %s
/AP <</N %d 0 R>>
/F 4
/P %d 0 R
/FT
/Sig
%s
/T(Signature%d)
/V %d 0 R
''' % (
                             b'/Widget' if udct.get(b'sigbutton', False) else b'/Square',
                             pdfar,
                             no + 4,
                             page,
                             b'/SM(TabletPOSinline)' if udct.get(b'sigbutton', False) else b'',
                             nsig, nav + 1)),
            visual,
        ]
        return b''.join(obj), nav

    def makevisualization(self, no, udct, nsig, page):
        image = udct.get(b'signature_img', b'').decode('utf8')
        if image:
            return self.imagevisual(image, no, udct, nsig, page)
        return self.textvisual(no, udct, nsig, page)

    def makepdf(self, pdfdata1, udct, zeros):
        parser = PDFParser(BytesIO(pdfdata1))
        document = PDFDocument(parser, fallback=False)

        prev = document.find_xref(parser)
        info = document.xrefs[0].trailer['Info'].objid
        root = document.xrefs[0].trailer['Root'].objid
        size = 1
        # calculate last object id, size is only xref size but not count of object in xref
        for ref in document.xrefs:
            if isinstance(ref, PDFXRefStream):
                no = max(ref.ranges, key=operator.itemgetter(1))[1]
            else:
                if len(ref.offsets) == 0:
                    no = 0
                else:
                    no = max(ref.offsets.keys())
            size = max(size, no)
        pages = len(document.getobj(document.catalog['Pages'].objid)['Kids'])
        page = udct.get(b'sigpage', 0) if 0 <= udct.get(b'sigpage', 0) <= pages - 1 else 0
        page = document.getobj(document.catalog['Pages'].objid)['Kids'][page].objid

        nsig, fields = self.getfields(root, document)
        annots = self.getannots(page, document)

        infodata = self.getdata(pdfdata1, info, prev, document)
        rootdata = self.getdata(pdfdata1, root, prev, document, ('AcroForm',))
        pagedata = self.getdata(pdfdata1, page, prev, document, ('Annots',))

        no = size + 1
        visualization, nav = self.makevisualization(no, udct, nsig, page)
        objs = [
            self.makeobj(page, (b'/Annots[%s%d 0 R]' % (
                annots, no + 3) + pagedata)),
            self.makeobj(no + 0, infodata),
            self.makeobj(no + 1, (b'/AcroForm %d 0 R' % (no + 2)) + rootdata),
            self.makeobj(no + 2, b'/Fields[%s%d 0 R]/SigFlags %d' % (
                fields,
                no + 3, udct[b'sigflags'])),
            visualization,
            self.makeobj(nav + 1, (b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/ContactInfo(%s)\
/Filter/Adobe.PPKLite/Location(%s)/M(D:%s)/Prop_Build<</App<</Name/>>>>/Reason(%s)/SubFilter/adbe.pkcs7.detached/Type/Sig\
/Contents <' % (udct[b'contact'], udct[b'location'], udct[b'signingdate'], udct[b'reason'])) + zeros + b'>'),
        ]

        size = nav - no + 2
        pdfdata2 = b''.join(objs)
        startxref = len(pdfdata1)
        xref = b'xref\n%d 1\n%010d 00000 n \n%d %d\n' % (
            page, startxref + pdfdata2.find(b'\n%d 0 obj\n' % page) + 1, no, size)
        xref += b''.join(
            [b'%010d 00000 n \n' % (startxref + pdfdata2.find(b'\n%d 0 obj\n' % (no + i)) + 1) for i in range(size)])

        trailer = b'''\
trailer
<</ID [<%(h1)s><%(h2)s>]/Info %(info)d 0 R/Prev %(prev)d/Root %(root)d 0 R/Size %(size)d>>\n\
startxref\n\
%(startxref)d\n\
%%%%EOF\n\
'''
        trailer = trailer % {
            b'page': page,
            b'no': no,
            b'startxref': startxref + len(pdfdata2),
            b'prev': prev,
            b'info': no + 0,
            b'root': no + 1,
            b'size': size,
            b'h1': hashlib.md5(pdfdata1).hexdigest().upper().encode('ascii'),
            b'h2': hashlib.md5(pdfdata2).hexdigest().upper().encode('ascii'),
        }

        pdfdata2 = pdfdata2 + xref + trailer

        return pdfdata2

    def sign(self, datau, dct, key, cert, othercerts, algomd, hsm):
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

        contents = signer.sign(None, key, cert, othercerts, algomd, True, md, hsm)
        contents = self.aligned(contents)
        pdfdata2 = pdfdata2.replace(zeros, contents, 1)

        return pdfdata2


def sign(datau, udct, key, cert, othercerts, algomd, hsm=None):
    cls = SignedData()
    return cls.sign(datau, udct, key, cert, othercerts, algomd, hsm)
