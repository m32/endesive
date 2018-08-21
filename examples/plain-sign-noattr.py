#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.plain import sign
from oscrypto import asymmetric

def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('plain-unsigned.txt', 'rb').read()
    datas = sign.sign(datau, p12[0], p12[1], [], 'sha256', attrs=False)
    open('plain-signed-noattr.txt', 'wb').write(datas)

main()
