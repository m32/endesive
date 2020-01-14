# *-* coding: utf-8 *-*
import sys
from email import message_from_string

from asn1crypto import cms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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
            if part.get_content_type() not in (
                'application/x-pkcs7-mime',
                'application/pkcs7-mime',
            ):
                continue
            data = part.get_payload(decode=True)
            break
        if data is None:
            return

        signed_data = cms.ContentInfo.load(data)['content']
        # signed_data.debug()

        algo = signed_data['encrypted_content_info']['content_encryption_algorithm']['algorithm'].native
        param = signed_data['encrypted_content_info']['content_encryption_algorithm']['parameters'].native
        edata = signed_data['encrypted_content_info']['encrypted_content'].native
        pkey = signed_data['recipient_infos'].native[0]['encrypted_key']

        keyalgo = signed_data['recipient_infos'].native[0]['key_encryption_algorithm']
        if keyalgo['algorithm'] == 'rsaes_oaep':
            keyparam = keyalgo['parameters']
            mga = keyparam['mask_gen_algorithm']
            mgh = getattr(hashes, mga['parameters']['algorithm'].upper())()
            pad = padding.OAEP(
                mgf=getattr(padding, mga['algorithm'].upper())(algorithm=mgh),
                algorithm=getattr(hashes, keyparam['hash_algorithm']['algorithm'].upper())(),
                label=keyparam['p_source_algorithm']['parameters']
            )
            udata = key.decrypt(pkey, pad)
        elif keyalgo['algorithm'] == 'rsaes_pkcs1v15':
            udata = key.decrypt(pkey, padding.PKCS1v15())
        else:
            raise ValueError('Unknown key algorithm', keyalgo['algorithm'])

        algorithm, mode = algo.split('_', 1)
        algorithm = algorithm.upper()
        if algorithm in (
            'AES128',
            'AES192',
            'AES256',
        ):
            cipher = Cipher(
                algorithms.AES(udata),
                getattr(modes, mode.upper())(param),
                default_backend()
            )
        elif algorithm == 'TRIPLEDES':
            # XXX howto decode parameters to CBC mode ?
            mode = 'cbc'
            cipher = Cipher(
                algorithms.TripleDES(udata),
                getattr(modes, mode.upper())(param),
                default_backend()
            )
        else:
            raise ValueError('Unknown algorithm', algo)

        decryptor = cipher.decryptor()
        udata = decryptor.update(edata) + decryptor.finalize()
        if keyalgo['algorithm'] != 'rsaes_oaep':
            nb = ord(udata[-1]) if sys.version[0] < '3' else udata[-1]
            udata = udata[:-nb]
        return udata


def decrypt(data, key):
    cls = DecryptedData()
    return cls.decrypt(data, key)
