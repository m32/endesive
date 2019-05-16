# *-* coding: utf-8 *-*
import sys
from email import message_from_string

from asn1crypto import cms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding


class DecryptedData(object):

    def decrypt(self, data, key):
        msg = message_from_string(data)
        data = None
        for part in msg.walk():
            # multipart/* are just containers
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get_content_type() != 'application/x-pkcs7-mime':
                continue
            data = part.get_payload(decode=True)
            break
        if data is None:
            return

        signed_data = cms.ContentInfo.load(data)['content']

        algo = signed_data['encrypted_content_info']['content_encryption_algorithm']['algorithm'].native
        param = signed_data['encrypted_content_info']['content_encryption_algorithm']['parameters'].native
        edata = signed_data['encrypted_content_info']['encrypted_content'].native
        pkey = signed_data['recipient_infos'].native[0]['encrypted_key']

        udata = key.decrypt(pkey, padding.PKCS1v15())
        cipher = Cipher(algorithms.AES(udata), getattr(modes, algo.split('_', 1)[1].upper())(param), default_backend())
        decryptor = cipher.decryptor()
        udata = decryptor.update(edata) + decryptor.finalize()
        nb = ord(udata[-1]) if sys.version[0] < '3' else udata[-1]
        udata = udata[:-nb]
        return udata


def decrypt(data, key):
    cls = DecryptedData()
    return cls.decrypt(data, key)
