#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import email


def main():
    trusted_cert_pems = (open('demo2_ca.crt.pem', 'rt').read(),)

    for fname in (
            'smime-ssl-signed-attr.txt',
            'smime-ssl-signed-noattr.txt',
            'smime-signed-attr.txt',
            'smime-signed-attr-custom.txt',
            'smime-signed-noattr.txt',
    ):
        print('*' * 20, fname)
        try:
            datae = open(fname, 'rt', encoding='utf-8').read()
        except FileNotFoundError:
            print('no such file')
            continue
        (hashok, signatureok, certok) = email.verify(datae, trusted_cert_pems)
        print('signature ok?', signatureok)
        print('hash ok?', hashok)
        print('cert ok?', certok)


main()
