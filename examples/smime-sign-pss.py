#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from OpenSSL.crypto import load_pkcs12
from endesive import email


def main():
    p12 = load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('smime-unsigned.txt', 'rb').read()
    datas = email.sign(datau,
        p12.get_privatekey().to_cryptography_key(),
        p12.get_certificate().to_cryptography(),
        [],
        'sha512',
        attrs=True,
        pss=True
    )
    open('smime-signed-pss.txt', 'wb').write(datas)


main()
