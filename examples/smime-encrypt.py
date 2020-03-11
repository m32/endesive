#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from cryptography import x509
from cryptography.hazmat import backends
from endesive import email, signer


def load_cert(relative_path):
    with open(relative_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), backends.default_backend())


def main():
    certs = (
        load_cert('demo2_user1.crt.pem'),
    )
    datau = open('smime-unsigned.txt', 'rb').read()
    datae = email.encrypt(datau, certs, 'aes256_ofb')
    open('smime-encrypted.txt', 'wt').write(datae)
    datae = email.encrypt(datau, certs, 'aes256_ofb', True)
    open('smime-encrypted-oaep.txt', 'wt').write(datae)


main()
