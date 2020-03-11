# *-* coding: utf-8 *-*
import sys
import os
from email.mime.application import MIMEApplication

from asn1crypto import cms, core, algos
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding

from endesive import signer


class EncryptedData(object):

    def email(self, data, oaep):
        prefix = ['x-', ''][oaep]
        msg = MIMEApplication(data)
        del msg['Content-Type']
        msg['Content-Disposition'] = 'attachment; filename="smime.p7m"'
        msg['Content-Type'] = 'application/%spkcs7-mime; smime-type=enveloped-data; name="smime.p7m"' % prefix

        data = msg.as_string()
        return data

    def pad(self, s, block_size):
        n = (block_size - len(s)) % block_size
        n = bytes([n] * n)
        return s + n

    def recipient_info(self, cert, session_key, oaep):
        public_key = cert.public_key()
        cert = signer.cert2asn(cert)

        tbs_cert = cert['tbs_certificate']
        # TODO: use subject_key_identifier when available
        if oaep:
            encrypted_key = public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None
                )
            )
            kea = cms.KeyEncryptionAlgorithm({
                'algorithm': cms.KeyEncryptionAlgorithmId('rsaes_oaep'),
                'parameters': algos.RSAESOAEPParams({
                    'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha512'}),
                    'mask_gen_algorithm': algos.MaskGenAlgorithm({
                        'algorithm': algos.MaskGenAlgorithmId('mgf1'),
                        'parameters': {
                            'algorithm': algos.DigestAlgorithmId('sha512'),
                        }
                    }),
                    'p_source_algorithm': algos.PSourceAlgorithm({
                        'algorithm': algos.PSourceAlgorithmId('p_specified'),
                        'parameters': b'',
                    })
                })
            })
        else:
            kea = {'algorithm': 'rsa'}
            encrypted_key = public_key.encrypt(session_key, padding.PKCS1v15())
        result = cms.RecipientInfo(
            name='ktri',
            value={
                'version': 'v0',
                'rid': cms.RecipientIdentifier(
                    name='issuer_and_serial_number',
                    value={
                        'issuer': tbs_cert['issuer'],
                        'serial_number': tbs_cert['serial_number']
                    }
                ),
                'key_encryption_algorithm': kea,
                'encrypted_key': core.OctetString(encrypted_key)
            }
        )
        return result

    def build(self, data, certs, algo, oaep):
        key_size = {
            'aes128': 16,
            'aes192': 24,
            'aes256': 32,
        }[algo.split('_', 1)[0]]
        block_size = 16
        session_key = os.urandom(key_size)
        iv = os.urandom(block_size)
        cipher = Cipher(
            algorithms.AES(session_key),
            getattr(modes, algo.split('_', 1)[1].upper())(iv),
            default_backend()
        )

        if not oaep:
            data = self.pad(data, block_size)

        encryptor = cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()

        recipient_infos = []
        for cert in certs:
            recipient_info = self.recipient_info(cert, session_key, oaep)
            recipient_infos.append(recipient_info)

        enveloped_data = cms.ContentInfo({
            'content_type': 'enveloped_data',
            'content': {
                'version': 'v0',
                'recipient_infos': recipient_infos,
                'encrypted_content_info': {
                    'content_type': 'data',
                    'content_encryption_algorithm': {
                        'algorithm': algo,
                        'parameters': iv
                    },
                    'encrypted_content': data
                }
            }
        })
        data = self.email(enveloped_data.dump(), oaep)
        return data


def encrypt(data, certs, algo='aes256_cbc', oaep=False):
    assert algo[:3] == 'aes' and algo.split('_', 1)[1] in ('cbc', 'ofb')
    cls = EncryptedData()
    return cls.build(data, certs, algo, oaep)
