#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import plain


def main():
    trusted_cert_pems = (open('demo2_ca.crt.pem', 'rt').read(),)
    datau = open('plain-unsigned.txt', 'rb').read()
    for fname in (
            'plain-ssl-signed-attr.txt',
            'plain-ssl-signed-noattr.txt',
            'plain-signed-attr.txt',
            'plain-signed-noattr.txt',
            'plain-signed-pss.txt',
    ):
        print('*' * 20, fname)
        try:
            datas = open(fname, 'rb').read()
        except FileNotFoundError:
            print("no such file", fname)
            continue
        (hashok, signatureok, certok) = plain.verify(datas, datau, trusted_cert_pems)
        print('signature ok?', signatureok)
        print('hash ok?', hashok)
        print('cert ok?', certok)


main()
