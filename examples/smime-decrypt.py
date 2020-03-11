#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import io
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import email


def main():
    with open('demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    for fname in (
        'smime-ssl-encrypted.txt',
        'smime-ssl-oaep-encrypted.txt',
        'smime-encrypted.txt',
        'smime-encrypted-oaep.txt',
    ):
        print('*' * 20, fname)
        try:
            datae = io.open(fname, 'rt', encoding='utf-8').read()
        except:
            print('no such file')
            continue
        datad = email.decrypt(datae, p12[0])
        datad = datad.decode('utf-8')
        io.open(fname.replace('encrypted', 'decrypted'), 'wt', encoding='utf-8').write(datad)


main()
