# *-* coding: utf-8 *-*
import os
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from asn1crypto import cms, core
from oscrypto import asymmetric

class EncryptedData(object):

    def email(self, data):
        msg = MIMEApplication(data)
        del msg['Content-Type']
        msg['Content-Disposition'] = 'attachment; filename="smime.p7m"'
        msg['Content-Type'] = 'application/x-pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"'

        data = msg.as_string()
        return data


    @property
    def parameters(self):
        return self._iv

    @property
    def session_key(self):
        return self._session_key

    @staticmethod
    def _pad(s, block_size):
        n = block_size - len(s) % block_size
        return s + n * chr(n)

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        data = self.pad(data, self.block_size)
        data = encryptor.update(data) + encryptor.finalize()

    def pad(self, s, block_size):
        n = block_size - len(s) % block_size
        n = bytes([n]*n)
        return s + n

    def recipient_info(self, cert, session_key):
        public = asymmetric.load_public_key(cert.public_key)
        encrypted_key = asymmetric.rsa_pkcs1v15_encrypt(public, session_key)
        tbs_cert = cert['tbs_certificate']
        # TODO: use subject_key_identifier when available
        return cms.RecipientInfo(
            name = u'ktri',
            value = {
                'version': u'v0',
                'rid': cms.RecipientIdentifier(
                    name = u'issuer_and_serial_number',
                    value = {
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

    def build(self, data, certs):
        key_size = 32
        block_size = 16
        session_key = os.urandom(key_size)
        iv = os.urandom(block_size)
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), default_backend())

        data = self.pad(data, block_size)

        encryptor = cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()

        recipient_infos = []
        for cert in certs:
            recipient_info = self.recipient_info(cert, session_key)
        recipient_infos.append(recipient_info)

        enveloped_data = cms.ContentInfo({
            'content_type': u'enveloped_data',
            'content': {
                'version': u'v0',
                'recipient_infos': recipient_infos,
                'encrypted_content_info': {
                    'content_type': u'data',
                    'content_encryption_algorithm': {
                        'algorithm': u'aes256_cbc',
                        'parameters': iv
                    },
                    'encrypted_content': data
                }
            }
        })
        data = self.email(enveloped_data.dump())
        return data

def encrypt(data, certs):
    cls = EncryptedData()
    return cls.build(data, certs)
