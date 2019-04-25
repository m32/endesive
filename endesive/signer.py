# *-* coding: utf-8 *-*
from __future__ import unicode_literals

import sys
import hashlib
from datetime import datetime

from asn1crypto import cms, algos, core, pem, x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def cert2asn(cert, cert_bytes=True):
    if cert_bytes:
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    else:
        cert_bytes = cert
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def sign(datau, key, cert, othercerts, hashalgo, attrs=True, signed_value=None):
    if signed_value is None:
        signed_value = getattr(hashlib, hashalgo)(datau).digest()
    signed_time = datetime.now()

    cert = cert2asn(cert)
    certificates = []
    certificates.append(cert)
    for i in range(len(othercerts)):
        certificates.append(cert2asn(othercerts[i]))

    hashalgo = unicode(hashalgo) if sys.version[0] < '3' else hashalgo

    signer = {
        'version': 'v1',
        'sid': cms.SignerIdentifier({
            'issuer_and_serial_number': cms.IssuerAndSerialNumber({
                'issuer': cert.issuer,
                'serial_number': cert.serial_number,
            }),
        }),
        'digest_algorithm': algos.DigestAlgorithm({'algorithm': hashalgo}),
        'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
        'signature': signed_value,
    }
    if attrs:
        if attrs is True:
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
        else:
            signer['signed_attrs'] = attrs
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
    signed_value_signature = key.sign(
        tosign,
        padding.PKCS1v15(),
        getattr(hashes, hashalgo.upper())()
    )
    # signed_value_signature = core.OctetString(signed_value_signature)
    datas['content']['signer_infos'][0]['signature'] = signed_value_signature

    return datas.dump()
