# *-* coding: utf-8 *-*
from datetime import datetime
import hashlib
from asn1crypto import x509, pem, util, cms, algos, core
from oscrypto import keys, asymmetric
from . import fpdf

class FPDF(fpdf.FPDF):
    signer = True
    def pkcs11_setup(self, key, cert, othercerts, algomd, algosig):
        self.pkcs11zeros = self.pkcs11_aligned(b'\0')
        self.pkcs11annot = 0
        self.pkcs11pdfbr = 0
        self.pkcs11key = key
        self.pkcs11cert = cert
        self.pkcs11certs = othercerts
        self.pkcs11algomd = algomd
        self.pkcs11algosig = algosig

    def pkcs11_signature(self):
        self._newobj()
        self.pkcs11annot = self.n
        self._out(b'<</F 132/Type/Annot/Subtype/Widget/Rect[0 0 0 0]/FT/Sig/DR<<>>/T(signature%d)/V %d 0 R>>' %(self.pkcs11annot, self.pkcs11annot+1))
        self._out(b'endobj')

        self._newobj()
        self.buffer += b'<</Contents <'
        self.pkcs11pdfbr = len(self.buffer)
        self.buffer += self.pkcs11zeros
        self._out(b'>\n/Type/Sig/SubFilter/adbe.pkcs7.detached/Location(TriSoft Sp. z o.o.)/M(D:20180802134926+02\'00\')')
        self._out(b'/ByteRange [0000000000 0000000000 0000000000 0000000000]/Filter/Adobe.PPKLite/Reason(Faktura Podpisana Elektronicznie)/ContactInfo(mak@trisoft.com.pl)>>')
        self._out(b'endobj')

    def pkcs11_sign(self):
        sbr = b'SIGNER 0 R'
        dbr = b'%-6d 0 R' %self.pkcs11annot
        self.buffer = self.buffer.replace(sbr, dbr, 2)

        br = [0, self.pkcs11pdfbr-1, self.pkcs11pdfbr+0x4000+1, len(self.buffer)-self.pkcs11pdfbr-0x4000-1]
        sbr = b'[0000000000 0000000000 0000000000 0000000000]'
        dbr = b'[%010d %010d %010d %010d]' % tuple(br)
        self.buffer = self.buffer.replace(sbr, dbr, 1)

        md = getattr(hashlib, self.pkcs11algomd)()
        b1 = self.buffer[:br[1]]
        b2 = self.buffer[br[2]:]
        md.update(b1)
        md.update(b2)
        signed_md = md.digest()
        signed_time = datetime.now()

        contents = self.pkcs11sign(signed_md, signed_time)
        contents = self.pkcs11_aligned(contents)

        self.buffer = self.buffer.replace(self.pkcs11zeros, contents)

    def pkcs11sign(self, signed_md, signed_time):

        certificates = [self.pkcs11cert.asn1]
        for cert in self.pkcs11certs:
            certificates.append(cert.asn1)

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
        signed_value_signature = asymmetric.rsa_pkcs1v15_sign(self.pkcs11key, tosign, self.pkcs11algosig)

        signer = {
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': certificates[0].issuer,
                    'serial_number': certificates[0].serial_number,
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': self.pkcs11algomd}),
            'signed_attrs': signedattrs,
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
            'signature': signed_value_signature,
        }
        config = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((
                algos.DigestAlgorithm({'algorithm': self.pkcs11algomd}),
            )),
            'encap_content_info': {
                'content_type': 'data',
            },
            'certificates': certificates,
            #'crls': [],
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

    def pkcs11_aligned(self, data):
        data = b''.join([b'%02x' % i for i in data])
        nb = 0x4000 - len(data)
        data = data + b'0'*(0x4000 - len(data))
        return data
