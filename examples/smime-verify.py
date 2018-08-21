#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from OpenSSL import crypto
from endesive.email import verify
from oscrypto import asymmetric

def main():
    cls = verify.VerifyData()
    trusted_cert_pems = (open('demo2_ca.crt.pem', 'rt').read(),)
    for trusted_cert_pem in trusted_cert_pems:
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
        cls.add_cert(trusted_cert)

    for fname in (
        'smime-ssl-signed-attr.txt',
        'smime-ssl-signed-noattr.txt',
        'smime-signed-attr.txt',
        'smime-signed-noattr.txt',
    ):
        print('*'*20, fname)
        datae = open(fname, 'rt', encoding='utf-8').read()
        (hashok, signatureok, certok) = cls.verify(datae)
        print('signature ok?', signatureok)
        print('hash ok?', hashok)
        print('cert ok?', certok)

main()
