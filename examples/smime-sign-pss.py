#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import email


def main():
    with open('ca/demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    datau = open('smime-unsigned.txt', 'rb').read()
    datas = email.sign(datau,
        p12[0], p12[1], p12[2],
        'sha512',
        attrs=True,
        pss=True
    )
    open('smime-signed-pss.txt', 'wb').write(datas)


main()
