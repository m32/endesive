# *-* coding: utf-8 *-*
from datetime import datetime
import hashlib
from io import BytesIO
from asn1crypto import cms, algos, core
from oscrypto import asymmetric
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdftypes import PDFObjRef

class SignedData(object):

    def pkcs11(self, key, cert, othercerts, signed_md, signed_time, algomd, algosig):

        certificates = [cert.asn1]
        for i in range(len(othercerts)):
            certificates.append(cert.asn1)

        signedattrs = cms.CMSAttributes([
            cms.CMSAttribute({
                'type': cms.CMSAttributeType(u'content_type'),
                'values': (u'data',),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType(u'message_digest'),
                'values': (signed_md,),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType(u'signing_time'),
                'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
            }),
        ])

        tosign = signedattrs.dump()
        tosign = b'\x31' + tosign[1:]
        signed_value_signature = asymmetric.rsa_pkcs1v15_sign(key, tosign, algosig)

        signer = {
            'version': u'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': cert.asn1.issuer,
                    'serial_number': cert.asn1.serial_number,
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': algomd}),
            'signed_attrs': signedattrs,
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': u'rsassa_pkcs1v15'}),
            'signature': signed_value_signature,
        }
        config = {
            'version': u'v1',
            'digest_algorithms': cms.DigestAlgorithms((
                algos.DigestAlgorithm({'algorithm': algomd}),
            )),
            'encap_content_info': {
                'content_type': u'data',
            },
            'certificates': certificates,
            #'crls': [],
            'signer_infos': [
                signer,
            ],
        }
        sdata = cms.ContentInfo({
            'content_type': cms.ContentType(u'signed_data'),
            'content': cms.SignedData(config),
        })

        sdata = sdata.dump()
        return sdata

    def aligned(self, data):
        data = b''.join([b'%02x' % i for i in data])
        nb = 0x4000 - len(data)
        data = data + b'0'*(0x4000 - len(data))
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
        i0 = data.find(b'<<')+2
        i1 = data.rfind(b'>>')
        data = data[i0:i1]
        return data

    def makeobj(self, no, data):
        return (b'%d 0 obj\n<<' % no)+data+b'>>\nendobj\n'

    def makepdf(self, pdfdata1, zeros):
        parser = PDFParser(BytesIO(pdfdata1))
        document = PDFDocument(parser, fallback=False)

        prev = document.find_xref(parser)
        info = document.xrefs[0].trailer['Info'].objid
        root = document.xrefs[0].trailer['Root'].objid
        page = None
        for i in document.catalog['OpenAction']:
            if isinstance(i, PDFObjRef):
                page = i.objid
        infodata = self.getdata(pdfdata1, info, prev, document).strip()
        rootdata = self.getdata(pdfdata1, root, prev, document).strip()
        pagedata = self.getdata(pdfdata1, page, prev, document).strip()

        no = info
        objs = [
            self.makeobj(page, (b'/Annots[%d 0 R]' % (no+3))+pagedata),
            self.makeobj(no+0, infodata),
            self.makeobj(no+1, (b'/AcroForm %d 0 R' % (no+2))+rootdata),
            self.makeobj(no+2, b'/Fields[%d 0 R]/SigFlags 3' % (no+3)),
            self.makeobj(no+3, b'/AP<</N %d 0 R>>/F 132/FT/Sig/P %d 0 R/Rect[0 0 0 0]/Subtype/Widget/T(Signature1)/V %d 0 R' % ( no+4, page, no+5 )),
            self.makeobj(no+4, b'/BBox[0 0 0 0]/Filter/FlateDecode/Length 8/Subtype/Form/Type/XObject'),
            b'stream\n\x78\x9C\x03\x00\x00\x00\x00\x01\nendstream\n',
            self.makeobj(no+5, b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/ContactInfo()\
/Filter/Adobe.PPKLite/Location(TestCity)/M(D:20180802230553+02\'00\')/Prop_Build<</App<</Name/>>>>/Reason(Test 1)/SubFilter/adbe.pkcs7.detached/Type/Sig\
/Contents <'+zeros+b'>'),
        ]

        pdfdata2 = b''.join(objs)
        xref = b'''\
xref\n\
%(page)d 1\n\
%(o03)010d 00000 n \n\
%(no)d 6\n\
%(o08)010d 00000 n \n\
%(o09)010d 00000 n \n\
%(o10)010d 00000 n \n\
%(o11)010d 00000 n \n\
%(o12)010d 00000 n \n\
%(o13)010d 00000 n \n\
'''
        startxref = len(pdfdata1)
        dct = {
            b'page': page,
            b'no': no,
            b'startxref': startxref+len(pdfdata2),
            b'prev': prev,
            b'info': no+0,
            b'root': no+1,
        }
        for i in range(14):
            dct[b'o%02d'%i] = startxref+pdfdata2.find(b'\n%d 0 obj\n'%i)+1

        trailer = b'''\
trailer
<</ID [<1><2>]/Info %(info)d 0 R/Prev %(prev)d/Root %(root)d 0 R/Size 14>>\n\
startxref\n\
%(startxref)d\n\
%%%%EOF\n\
'''

        xref = xref % dct
        trailer = trailer % dct

        pdfdata2 = pdfdata2 + xref + trailer

        return pdfdata2

    def sign(self, datau, key, cert, othercerts, algomd, algosig):
        zeros = self.aligned(b'\0')

        pdfdata2 = self.makepdf(datau, zeros)


        startxref = len(datau)
        pdfbr1 = pdfdata2.find(zeros)
        pdfbr2 = pdfbr1+len(zeros)
        br = [0, startxref+pdfbr1-1, startxref+pdfbr2+1, len(pdfdata2)-pdfbr2-1]
        brfrom = b'[0000000000 0000000000 0000000000 0000000000]'
        brto = b'[%010d %010d %010d %010d]'%tuple(br)
        pdfdata2 = pdfdata2.replace(brfrom, brto, 1)

        md = getattr(hashlib, algomd)()
        md.update(datau)
        b1 = pdfdata2[:br[1]-startxref]
        b2 = pdfdata2[br[2]-startxref:]
        md.update(b1)
        md.update(b2)
        md = md.digest()

        signed_md = md
        signed_time = datetime.now()
        contents = self.pkcs11(key, cert, othercerts, signed_md, signed_time, algomd, algosig)
        contents = self.aligned(contents)
        pdfdata2 = pdfdata2.replace(zeros, contents, 1)

        return pdfdata2


def sign(datau, key, cert, othercerts, algomd, algosig):
    cls = SignedData()
    return cls.sign(datau, key, cert, othercerts, algomd, algosig)
