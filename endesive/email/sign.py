# *-* coding: utf-8 *-*
import base64

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from endesive import signer


class SignedData(object):

    def email(self, hashalgo, datau, datas, prefix):
        s = b'''\
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/%spkcs7-signature"; micalg="%s"; boundary="----46F1AAD10BE922477643C0A33C40D389"

This is an S/MIME signed message

------46F1AAD10BE922477643C0A33C40D389
%s
------46F1AAD10BE922477643C0A33C40D389
Content-Type: application/%spkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

%s
------46F1AAD10BE922477643C0A33C40D389--

''' % (prefix, hashalgo, datau, prefix, datas)
        return s

    def build(self, datau, key, cert, othercerts, hashalgo, attrs, pss=False):
        datau = datau.replace(b'\n', b'\r\n')
        datas = signer.sign(datau, key, cert, othercerts, hashalgo, attrs, pss=pss)
        datas = base64.encodebytes(datas)
        if hashalgo == 'sha1':
            hashalgo = b'sha1'
        elif hashalgo == 'sha256':
            hashalgo = b'sha-256'
        elif hashalgo == 'sha512':
            hashalgo = b'sha-512'
        prefix = [b'x-', b''][pss]
        data = self.email(hashalgo, datau, datas, prefix)
        return data


def sign(datau:bytes, key: PrivateKeyTypes, cert: x509.Certificate, certs: list[x509.Certificate], hashalgo='sha1', attrs=True, pss=False)->bytes:
    """
    Sign data with private key and encapsulate the result (data and signature) as S/MIME message.

    :param datau: Data to sign (bytes).
    :param key: Private key to sign with (PrivateKeyTypes).
    :param cert: Certificate to sign with (x509.Certificate).
    :param certs: List of additional certificates (list of x509.Certificate).
    :param hashalgo: Hash algorithm to use (str, default 'sha1').
    :param attrs: Whether to include attributes (bool, default True).
    :param pss: Whether to use PSS padding (bool, default False).
    :return: Signed data as bytes.
    """
    cls = SignedData()
    return cls.build(datau, key, cert, certs, hashalgo, attrs, pss)
