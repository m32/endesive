import hashlib

from asn1crypto import algos, cms, core, pem, x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive import email


def main():
    with open('ca/demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    datau = open('generated/smime-unsigned.txt', 'rb').read()

    datau1 = datau.replace(b'\n', b'\r\n')
    hashalgo = 'sha256'
    signed_value = getattr(hashlib, hashalgo)(datau1).digest()
    def attrs_callback(signed_value):
        return [
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('content_type'),
                'values': ('data',),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': (signed_value,),
            }),
        ]

    datas = email.sign(datau,
        p12[0], p12[1], p12[2],
        'sha256',
        attrs=attrs_callback
    )
    open('generated/smime-signed-attr-custom.txt', 'wb').write(datas)


main()
