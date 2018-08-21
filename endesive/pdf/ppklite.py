#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
import hashlib
from asn1crypto import cms, algos, core
from oscrypto import asymmetric


class SignedData(object):

    def pkcs11(self, key, cert, othercertificates, signed_md, signed_time, algomd, algosig):

        certificates = [cert.asn1]
        for ocert in othercertificates:
            certificates.append(ocert.asn1)

        signer = {
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': cert.asn1.issuer,
                    'serial_number': cert.asn1.serial_number,
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': algomd}),
            'signed_attrs': [
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('content_type'),
                    'values': ('data',),
                }),
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('message_digest'),
                    'values': (signed_md,),
                }),
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('signing_time'),
                    'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
                }),
            ],
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
            'signature': b'',
        }
        config = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((
                algos.DigestAlgorithm({'algorithm': algosig}),
            )),
            'encap_content_info': {
                'content_type': 'data',
            },
            'certificates': certificates,
#            'crls': [],
            'signer_infos': [
                signer,
            ],
        }
        sdata = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(config),
        })
        tosign = sdata['content']['signer_infos'][0]['signed_attrs'].dump()
        tosign = b'\x31'+tosign[1:]

        signed_value_signature = asymmetric.rsa_pkcs1v15_sign(key, tosign, algosig)
        sdata['content']['signer_infos'][0]['signature'] = signed_value_signature
        return sdata.dump()

    def buildpdf(self, dct):
        pdfobj = b'''\
\n\
9 0 obj\n\
<<\n\
/ByteRange [0000000000 0000000000 0000000000 0000000000]\n\
/Contents <%(contents)s>\n\
/ContactInfo(%(contact)s)/Filter/Adobe.PPKLite/Location(%(location)s)\n\
/M(D:%(signingdate)s)/Prop_Build<</App<</Name/>>>>\n\
/Reason(%(reason)s)/SubFilter/adbe.pkcs7.detached/Type/Sig\n\
>>\n\
endobj\n\
7 0 obj\n\
<<\n\
/AcroForm 8 0 R/OpenAction[3 0 R /FitH null]/PageLayout/OneColumn/Pages 1 0 R/Type/Catalog\n\
>>\n\
endobj\n\
6 0 obj\n\
<<\n\
/CreationDate(D:%(creationdate)s)/ModDate(D:%(modificationdate)s)/Producer(%(producer)s)\n\
>>\n\
endobj\n\
3 0 obj\n\
<<\n\
/Annots[10 0 R]/Contents 4 0 R/Parent 1 0 R/Resources 2 0 R/Type/Page\n\
>>\n\
endobj\n\
8 0 obj\n\
<<\n\
/Fields[10 0 R]/SigFlags %(sigflags)d\n\
>>\n\
endobj\n\
10 0 obj\n\
<<\n\
/AP<</N 11 0 R>>/F 132/FT/Sig/P 3 0 R/Rect[0 0 0 0]/Subtype/Widget/T(%(signaturefield)s)/V 9 0 R\n\
>>\n\
endobj\n\
11 0 obj\n\
<<\n\
/BBox[0 0 0 0]/Filter/FlateDecode/Length 8/Subtype/Form/Type/XObject\n\
>>\n\
stream\n\
\x78\x9C\x03\x00\x00\x00\x00\x01\n\
endstream\n\
endobj\n\
''' % dct
        startxref = dct[b'zero']
        offsets = {}
        for no in range(12):
            offsets[b'o%d'%no] = startxref+pdfobj.find(b'%d 0 obj\n'%no)
        dct[b'startxref'] = startxref+len(pdfobj)
        xref = b'''\
xref
3 1\n\
%(o3)010d 00000 n \n\
6 6\n\
%(o6)010d 00000 n \n\
%(o7)010d 00000 n \n\
%(o8)010d 00000 n \n\
%(o9)010d 00000 n \n\
%(o10)010d 00000 n \n\
%(o11)010d 00000 n \n\
''' % offsets
        trailer = b'''\
trailer\n\
<<\n\
/ID [<%(id1)s><%(id2)s>]/Info 6 0 R/Prev %(prev)s/Root 7 0 R/Size 12\n\
>>\n\
%(producer)s\n\
startxref\n\
%(startxref)d\n\
%%%%EOF\n\
''' % dct

        pdfobj = pdfobj+xref+trailer
        byterange = [0, 0, 0, 0]
        s = b'/Contents <'
        s = pdfobj.find(s)+len(s)
        byterange[1] = startxref+s
        byterange[2] = startxref+s+len(dct[b'contents'])
        byterange[3] = len(pdfobj) - pdfobj.find(b'>', s)
        brfrom = b'[0000000000 0000000000 0000000000 0000000000]'
        brto = b'[%010d %010d %010d %010d]'%tuple(byterange)

        byterange[1] = s
        byterange[2] = s+len(dct[b'contents'])
        return byterange, pdfobj.replace(brfrom, brto)

    def aligned(self, data):
        data = b''.join([b'%02x' % i for i in data])
        nb = 0x4000 - len(data)
        data = data + b'0'*(0x4000 - len(data))
        return data

    def sign(self, datau, dct, key, cert, othercerts, algomd, algosig):
        i = datau.rfind(b'startxref')
        while datau[i] not in b'0123456789':
            i += 1
        j = i
        while datau[j] in b'0123456789':
            j += 1
        prev = datau[i:j]

        signed_md = getattr(hashlib, algomd)(b'A').digest()
        signed_time = datetime.datetime.now()
        contents = self.aligned(b'\0')

        dct.update({
            b'producer': b'endesive',
            b'signaturefield': b'signature1',
            b'prev': prev,
            b'contents': contents,
            b'id1': b'1',
            b'id2': b'2',
            b'zero':len(datau),
        })
        br, pdfdata2 = self.buildpdf(dct)
        assert pdfdata2[br[1]-1] == ord(b'<')
        assert pdfdata2[br[2]] == ord(b'>')

        tosign = pdfdata2[br[0]:br[0]+br[1]] + pdfdata2[br[2]:br[2]+br[3]]
        signed_md = getattr(hashlib, algomd)(pdfdata2).digest()
        contents = self.aligned(self.pkcs11(key, cert, othercerts, signed_md, signed_time, algomd, algosig))

        dct[b'contents'] = contents
        br, pdfdata3 = self.buildpdf(dct)

        return pdfdata3


def sign(datau, dct, key, cert, othercerts, algomd, algosig):
    cls = SignedData()
    return cls.sign(datau, dct, key, cert, othercerts, algomd, algosig)
