# *-* coding: utf-8 *-*
import base64

from endesive import signer


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

    def build(self, datau, key, cert, othercerts, hashalgo, attrs):
        datau = datau.replace(b'\n', b'\r\n')
        datas = signer.sign(datau, key, cert, othercerts, hashalgo, attrs)
        datas = base64.encodebytes(datas)
        if hashalgo == 'sha1':
            hashalgo = b'sha1'
        elif hashalgo == 'sha256':
            hashalgo = b'sha-256'
        data = self.email(hashalgo, datau, datas)
        return data


def sign(datau, key, cert, certs, hashalgo='sha1', attrs=True):
    cls = SignedData()
    return cls.build(datau, key, cert, certs, hashalgo, attrs)
