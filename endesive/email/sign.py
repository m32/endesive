# *-* coding: utf-8 *-*
import hashlib
import base64
from datetime import datetime
from asn1crypto import cms, algos, core
from oscrypto import asymmetric

class SignedData(object):

    def email(self, hashalgo, datau, datas):
        s = b'''\
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="%s"; boundary="----46F1AAD10BE922477643C0A33C40D389"

This is an S/MIME signed message

------46F1AAD10BE922477643C0A33C40D389
%s
------46F1AAD10BE922477643C0A33C40D389
Content-Type: application/x-pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

%s
------46F1AAD10BE922477643C0A33C40D389--

''' % (hashalgo, datau, datas)
        return s

    def build(self, datau, key,  cert, othercerts, hashalgo, attrs):
        datau = datau.replace(b'\n', b'\r\n')
        signed_value = getattr(hashlib, hashalgo)(datau).digest()
        signed_time = datetime.now()

        certificates = []
        certificates.append(cert.asn1)
        for i in range(len(othercerts)):
            certificates.append(othercerts[i].asn1)

        signer = {
            'version': 'v1',
            'sid': cms.SignerIdentifier({
                'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                    'issuer': cert.asn1.issuer,
                    'serial_number': cert.asn1.serial_number,
                }),
            }),
            'digest_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo}),
            'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
            'signature': signed_value,
        }
        if attrs:
            signer['signed_attrs'] = [
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('content_type'),
                    'values': ('data',),
                }),
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('message_digest'),
                    'values': (signed_value,),
                }),
                cms.CMSAttribute({
                    'type': cms.CMSAttributeType('signing_time'),
                    'values': (cms.Time({'utc_time': core.UTCTime(signed_time)}),)
                }),
            ]
        config = {
            'version': 'v1',
            'digest_algorithms': cms.DigestAlgorithms((
                algos.DigestAlgorithm({'algorithm': hashalgo}),
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
        if attrs:
            tosign = sdata['content']['signer_infos'][0]['signed_attrs'].dump()
            tosign = b'\x31' + tosign[1:]
        else:
            tosign = datau
        signed_value_signature = asymmetric.rsa_pkcs1v15_sign(key, tosign, hashalgo)
        #signed_value_signature = core.OctetString(signed_value_signature)
        sdata['content']['signer_infos'][0]['signature'] = signed_value_signature

        sdata = sdata.dump()
        sdata = base64.encodebytes(sdata)
        if hashalgo == 'sha1':
            hashalgo = b'sha1'
        elif hashalgo == 'sha256':
            hashalgo = b'sha-256'
        data = self.email(hashalgo, datau, sdata)
        return data

def sign(datau, key, cert, certs, hashalgo='sha1', attrs=True):
    cls = SignedData()
    return cls.build(datau, key, cert, certs, hashalgo, attrs)
