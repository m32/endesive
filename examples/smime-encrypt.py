#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from asn1crypto import x509, pem

from endesive import email


def load_cert(relative_path):
    with open(relative_path, 'rb') as f:
        cert_bytes = f.read()
        if pem.detect(cert_bytes):
            _, _, cert_bytes = pem.unarmor(cert_bytes)
        return x509.Certificate.load(cert_bytes)


def main():
    certs = (
        load_cert('demo2_user1.crt.pem'),
    )
    datau = open('smime-unsigned.txt', 'rb').read()
    datae = email.encrypt(datau, certs)
    open('smime-encrypted.txt', 'wt').write(datae)


main()
