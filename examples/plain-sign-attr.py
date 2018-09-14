#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from oscrypto import asymmetric

from endesive import plain


def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('plain-unsigned.txt', 'rb').read()
    datas = plain.sign(datau, p12[0], p12[1], [], 'sha256', attrs=True)
    open('plain-signed-attr.txt', 'wb').write(datas)


main()
