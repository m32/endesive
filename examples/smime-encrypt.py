#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from OpenSSL import crypto
from asn1crypto import x509, pem
from endesive import email, signer


def load_cert(relative_path):
    with open(relative_path, 'rb') as f:
        cert_bytes = f.read()
        return crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)


def main():
    certs = (
        load_cert('demo2_user1.crt.pem'),
    )
    datau = open('smime-unsigned.txt', 'rb').read()
    datae = email.encrypt(datau, certs, 'aes256_ofb')
    open('smime-encrypted.txt', 'wt').write(datae)


main()
