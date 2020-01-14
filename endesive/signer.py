# *-* coding: utf-8 *-*
from __future__ import unicode_literals

import sys
import hashlib
from datetime import datetime

import pytz
from asn1crypto import cms, algos, core, pem, x509, util
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils


def cert2asn(cert, cert_bytes=True):
    if cert_bytes:
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    else:
        cert_bytes = cert
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def sign(datau, key, cert, othercerts, hashalgo, attrs=True, signed_value=None, hsm=None, pss=False):
    if signed_value is None:
        signed_value = getattr(hashlib, hashalgo)(datau).digest()
    signed_time = datetime.now(tz=util.timezone.utc)

    if hsm is not None:
        keyid, cert = hsm.certificate()
        cert = cert2asn(cert, False)
        othercerts = []
    else:
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
        'signature': signed_value,
    }
    if not pss:
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'})
    else:
        salt_length = padding.calculate_max_pss_salt_length(key, hashes.SHA512)
        signer['signature_algorithm'] = algos.SignedDigestAlgorithm({
            'algorithm': 'rsassa_pss',
            'parameters': algos.RSASSAPSSParams({
                'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha512'}),
                'mask_gen_algorithm': algos.MaskGenAlgorithm({
                    'algorithm': algos.MaskGenAlgorithmId('mgf1'),
                    'parameters': {
                        'algorithm': algos.DigestAlgorithmId('sha512'),
                    }
                }),
                'salt_length': algos.Integer(salt_length),
                'trailer_field': algos.TrailerField(1)
            })
        })

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
    if hsm is not None:
        signed_value_signature = hsm.sign(keyid, tosign, hashalgo)
    else:
        if pss:
            hasher = hashes.Hash(hashes.SHA512(), backend=backends.default_backend())
            hasher.update(tosign)
            digest = hasher.finalize()
            signed_value_signature = key.sign(
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=salt_length
                ),
                utils.Prehashed(hashes.SHA512())
            )
        else:
            signed_value_signature = key.sign(
                tosign,
                padding.PKCS1v15(),
                getattr(hashes, hashalgo.upper())()
            )
    # signed_value_signature = core.OctetString(signed_value_signature)
    datas['content']['signer_infos'][0]['signature'] = signed_value_signature

    return datas.dump()
