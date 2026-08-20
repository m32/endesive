#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import io
from endesive import email


def main():
    trusted_cert_pems = (open('ca/demo2_ca.root.crt.pem', 'rb').read(),)

    for fname in (
        'generated/smime-signed-attr.txt',
        'generated/smime-signed-attr-custom.txt',
        'generated/smime-signed-hsm.txt',
        'generated/smime-signed-noattr.txt',
        'generated/smime-signed-pss.txt',
        'generated/smime-ssl-pss-signed.txt',
        'generated/smime-ssl-signed-attr.txt',
        'generated/smime-ssl-signed-noattr.txt',
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
