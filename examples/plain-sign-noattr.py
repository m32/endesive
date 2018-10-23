#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from OpenSSL.crypto import load_pkcs12
from endesive import plain


def main():
    p12 = load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('plain-unsigned.txt', 'rb').read()
    datas = plain.sign(datau,
        p12.get_privatekey().to_cryptography_key(),
        p12.get_certificate().to_cryptography(),
        [],
        'sha256',
        attrs=False
    )
    open('plain-signed-noattr.txt', 'wb').write(datas)


main()
