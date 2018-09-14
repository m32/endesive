# *-* coding: utf-8 *-*
import hashlib
from datetime import datetime

from asn1crypto import cms, algos, core
from oscrypto import asymmetric


def sign(datau, key, cert, othercerts, hashalgo, attrs=True, signed_value=None):
    if signed_value is None:
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
        # 'crls': [],
        'signer_infos': [
            signer,
        ],
    }
    datas = cms.ContentInfo({
        'content_type': cms.ContentType('signed_data'),
        'content': cms.SignedData(config),
    })
    if attrs:
        tosign = datas['content']['signer_infos'][0]['signed_attrs'].dump()
        tosign = b'\x31' + tosign[1:]
    else:
        tosign = datau
    signed_value_signature = asymmetric.rsa_pkcs1v15_sign(key, tosign, hashalgo)
    # signed_value_signature = core.OctetString(signed_value_signature)
    datas['content']['signer_infos'][0]['signature'] = signed_value_signature

    return datas.dump()
