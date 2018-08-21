# *-* coding: utf-8 *-*
import datetime
import hashlib
from asn1crypto import cms, algos, core
from oscrypto import asymmetric


class SignedData(object):
    def pkcs11(self, key, cert, othercerts, signed_md, signed_time, algomd, algosig):

        certificates = [cert.asn1]
        for i in range(len(othercerts)):
            certificates.append(othercerts[i].asn1)

        signedattrs = cms.CMSAttributes([
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
        ])

        tosign = signedattrs.dump()
        tosign = b'\x31' + tosign[1:]
        signed_value_signature = asymmetric.rsa_pkcs1v15_sign(key, tosign, algosig)

        signer = {
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': cert.asn1.issuer,
                    'serial_number': cert.asn1.serial_number,
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': algomd}),
            'signed_attrs': signedattrs,
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
            'signature': signed_value_signature,
        }
        config = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((
                algos.DigestAlgorithm({'algorithm': algomd}),
            )),
            'encap_content_info': {
                'content_type': 'data',
            },
            'certificates': certificates,
            # 'crls': [],
            'signer_infos': [
                signer,
            ],
        }
        sdata = cms.ContentInfo({
            'content_type': cms.ContentType('signed_data'),
            'content': cms.SignedData(config),
        })

        sdata = sdata.dump()
        return sdata

    def aligned(self, data):
        data = b''.join([b'%02x' % i for i in data])
        nb = 0x4000 - len(data)
        data = data + b'0' * (0x4000 - len(data))
        return data

    def sign(self, pdfdata, key, cert, certificates, algomd, algosig):

        i = pdfdata.rfind(b'startxref')
        while pdfdata[i] not in b'0123456789':
            i += 1
        j = i
        while pdfdata[j] in b'0123456789':
            j += 1
        prev = pdfdata[i:j]

        zeros = self.aligned(b'\0')

        pdfdata2 = b'''\
\n\
11 0 obj\n\
<<\n\
/ByteRange [0000000000 0000000000 0000000000 0000000000]\n\
/ContactInfo()\n\
/Contents <'''
        pdfbr1 = len(pdfdata2)
        pdfdata2 += zeros
        pdfbr2 = len(pdfdata2)
        pdfdata2 += b'''\
>/Filter/Adobe.PPKLite/Location(TestCity)/M(D:20180802230554+02'00')/Prop_Build<</App<</Name/>>>>/Reason(Test 1)/SubFilter/ETSI.CAdES.detached/Type/Sig>>\n\
endobj\n\
9 0 obj\n\
<</AcroForm 10 0 R/Extensions<</ESIC<</BaseVersion/1.7/ExtensionLevel 2>>>>/OpenAction[3 0 R /FitH null]/PageLayout/OneColumn/Pages 1 0 R/Type/Catalog>>\n\
endobj\n\
8 0 obj\n\
<</CreationDate(D:20180802220055)/ModDate(D:20180802230554+02'00')/Producer(iText)>>\n\
endobj\n\
3 0 obj\n\
<</Annots[12 0 R]/Contents 4 0 R/Parent 1 0 R/Resources 2 0 R/Type/Page>>\n\
endobj\n\
10 0 obj\n\
<</Fields[12 0 R]/SigFlags 3>>\n\
endobj\n\
12 0 obj\n\
<</AP<</N 13 0 R>>/F 132/FT/Sig/P 3 0 R/Rect[0 0 0 0]/Subtype/Widget/T(Signature1)/V 11 0 R>>\n\
endobj\n\
13 0 obj\n\
<</BBox[0 0 0 0]/Filter/FlateDecode/Length 8/Subtype/Form/Type/XObject>>stream\n\
\x78\x9C\x03\x00\x00\x00\x00\x01\n\
endstream\n\
endobj\n\
'''
        xref = b'''\
xref\n\
3 1\n\
%(o3)010d 00000 n \n\
8 6\n\
%(o8)010d 00000 n \n\
%(o9)010d 00000 n \n\
%(o10)010d 00000 n \n\
%(o11)010d 00000 n \n\
%(o12)010d 00000 n \n\
%(o13)010d 00000 n \n\
'''
        trailer = b'''\
trailer\n\
<</ID [<1><2>]/Info 8 0 R/Prev 903/Root 9 0 R/Size 14>>\n\
startxref\n\
%(startxref)d\n\
%%%%EOF\n\
'''
        startxref = len(pdfdata)
        dct = {}
        for no in range(14):
            dct[b'o%d' % no] = startxref + pdfdata2.find(b'\n%d 0 obj\n' % no) + 1
        dct[b'startxref'] = startxref + len(pdfdata2)
        dct[b'prev'] = prev

        xref = xref % dct
        trailer = trailer % dct

        pdfdata2 = pdfdata2 + xref + trailer

        br = [0, startxref + pdfbr1 - 1, startxref + pdfbr2 + 1, len(pdfdata2) - pdfbr2 - 1]
        brfrom = b'[0000000000 0000000000 0000000000 0000000000]'
        brto = b'[%010d %010d %010d %010d]' % tuple(br)
        pdfdata2 = pdfdata2.replace(brfrom, brto, 1)

        md = getattr(hashlib, algomd)()
        md.update(pdfdata)
        b1 = pdfdata2[:br[1] - startxref]
        b2 = pdfdata2[br[2] - startxref:]
        md.update(b1)
        md.update(b2)
        md = md.digest()

        signed_md = md
        signed_time = datetime.datetime.now()
        contents = self.pkcs11(key, cert, certificates, signed_md, signed_time, algomd, algosig)
        contents = self.aligned(contents)
        pdfdata2 = pdfdata2.replace(zeros, contents, 1)

        return pdfdata2


def sign(datau, key, cert, othercerts, algomd, algosig):
    cls = SignedData()
    return cls.sign(datau, key, cert, othercerts, algomd, algosig)
