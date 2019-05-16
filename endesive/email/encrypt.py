# *-* coding: utf-8 *-*
import sys
import os
from email.mime.application import MIMEApplication

from asn1crypto import cms, core
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding

from endesive import signer


class EncryptedData(object):

    def email(self, data):
        msg = MIMEApplication(data)
        del msg['Content-Type']
        msg['Content-Disposition'] = 'attachment; filename="smime.p7m"'
        msg['Content-Type'] = 'application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"'

        data = msg.as_string()
        return data

    def pad(self, s, block_size):
        n = (block_size - len(s)) % block_size
        n = bytes([n] * n)
        return s + n

    def recipient_info(self, cert, session_key):
        public_key = cert.get_pubkey().to_cryptography_key()
        encrypted_key = public_key.encrypt(session_key, padding.PKCS1v15())
        cert = signer.cert2asn(cert.to_cryptography())

        tbs_cert = cert['tbs_certificate']
        # TODO: use subject_key_identifier when available
        return cms.RecipientInfo(
            name=u'ktri',
            value={
                'version': u'v0',
                'rid': cms.RecipientIdentifier(
                    name=u'issuer_and_serial_number',
                    value={
                        'issuer': tbs_cert['issuer'],
                        'serial_number': tbs_cert['serial_number']
                    }
                ),
                'key_encryption_algorithm': {
                    'algorithm': u'rsa',
                },
                'encrypted_key': core.OctetString(encrypted_key)
            }
        )

    def build(self, data, certs, algo):
        key_size = {
            'aes128': 16,
            'aes192': 24,
            'aes256': 32,
        }[algo.split('_', 1)[0]]
        block_size = 16
        session_key = os.urandom(key_size)
        iv = os.urandom(block_size)
        cipher = Cipher(algorithms.AES(session_key), getattr(modes, algo.split('_', 1)[1].upper())(iv), default_backend())

        data = self.pad(data, block_size)

        encryptor = cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()

        recipient_infos = []
        for cert in certs:
            recipient_info = self.recipient_info(cert, session_key)
            recipient_infos.append(recipient_info)

        algo = unicode(algo) if sys.version[0] < '3' else algo

        enveloped_data = cms.ContentInfo({
            'content_type': u'enveloped_data',
            'content': {
                'version': u'v0',
                'recipient_infos': recipient_infos,
                'encrypted_content_info': {
                    'content_type': u'data',
                    'content_encryption_algorithm': {
                        'algorithm': algo,
                        'parameters': iv
                    },
                    'encrypted_content': data
                }
            }
        })
        data = self.email(enveloped_data.dump())
        return data


def encrypt(data, certs, algo=u'aes256_cbc'):
    assert algo[:3] == 'aes' and algo.split('_', 1)[1] in ('cbc', 'ofb')
    cls = EncryptedData()
    return cls.build(data, certs, algo)
