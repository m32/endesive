#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.pdf import cades
from oscrypto import asymmetric

def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('pdf.pdf', 'rb').read()
    datas = cades.sign(datau, p12[0], p12[1], [], 'sha256', 'sha256')
    with open('pdf-signed-cades.pdf', 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

main()
