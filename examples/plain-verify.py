#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.plain import verify
from oscrypto import asymmetric

def main():
    datau = open('plain-unsigned.txt', 'rb').read()
    for fname in (
        'plain-ssl-signed-attr.txt',
        'plain-ssl-signed-noattr.txt',
        'plain-signed-attr.txt',
        'plain-signed-noattr.txt',
    ):
        print('*'*20, fname)
        datae = open(fname, 'rb').read()
        cls = verify.VerifyData()
        (hashok, signatureok, certok) = cls.verify(datau, datae)
        print('signature ok?', signatureok)
        print('hash ok?', hashok)
        print('cert ok?', certok)

main()
