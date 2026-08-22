#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import plain


def main():
    trusted_cert_pems = (open('ca/demo2_ca.root.crt.pem', 'rb').read(),)
    datau = open('generated/plain-unsigned.txt', 'rb').read()
    for fname in (
            'generated/plain-ssl-signed-attr.txt',
            'generated/plain-ssl-signed-noattr.txt',
            'generated/plain-signed-attr.txt',
            'generated/plain-signed-noattr.txt',
            'generated/plain-signed-pss.txt',
    ):
        print('*' * 20, fname)
        try:
            datas = open(fname, 'rb').read()
        except FileNotFoundError:
            print("no such file", fname)
            continue
        result = plain.verify(datas, datau, trusted_cert_pems)
        print("signature ok?", result[0])
        print("hash ok?", result[1])
        print("cert ok?", result[2])
        print("ocsp ok?", result[3], "ocsp data:", result[4])
        print("tsp ok?", result[5], "tsp data:", result[6])


main()
