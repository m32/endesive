#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.email import sign
from oscrypto import asymmetric

def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('smime-unsigned.txt', 'rb').read()
    datas = sign.sign(datau, p12[0], p12[1], [], 'sha256', attrs=True)
    open('smime-signed-attr.txt', 'wb').write(datas)

main()
