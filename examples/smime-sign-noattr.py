#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from oscrypto import asymmetric

from endesive import email


def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('smime-unsigned.txt', 'rb').read()
    datas = email.sign(datau, p12[0], p12[1], [], 'sha256', attrs=False)
    open('smime-signed-noattr.txt', 'wb').write(datas)


main()
