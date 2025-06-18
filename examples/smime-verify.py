#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import io
from endesive import email


def main():
    trusted_cert_pems = (open('ca/root.pem', 'rb').read(),)

    for fname in (
        'smime-signed-attr.txt',
        'smime-signed-attr-custom.txt',
        'smime-signed-hsm.txt',
        'smime-signed-noattr.txt',
        'smime-signed-pss.txt',
        'smime-ssl-pss-signed.txt',
        'smime-ssl-signed-attr.txt',
        'smime-ssl-signed-noattr.txt',
    ):
        print('*' * 20, fname)
        try:
            datae = io.open(fname, 'rt', encoding='utf-8').read()
        except:
            print('no such file')
            continue
        (hashok, signatureok, certok) = email.verify(datae, trusted_cert_pems)
        print('signature ok?', signatureok)
        print('hash ok?', hashok)
        print('cert ok?', certok)


main()
