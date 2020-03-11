#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from oscrypto import keys
from endesive import email


def main():
    with open('demo2_user1.p12', 'rb') as f:
        key, cert, certe = keys.parse_pkcs12(f.read(), b'1234')
    datau = open('smime-unsigned.txt', 'rb').read()
    datas = email.sign(datau,
        key, cert, certe,
        'sha512',
        attrs=True,
        pss=True
    )
    open('smime-signed-pss-oscrypto.txt', 'wb').write(datas)


main()
