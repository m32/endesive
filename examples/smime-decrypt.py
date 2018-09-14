#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from oscrypto import asymmetric

from endesive import email


def main():
    key = asymmetric.load_private_key(open('demo2_user1.key.pem', 'rb').read(), '1234')
    for fname in (
            'smime-ssl-encrypted.txt',
            'smime-encrypted.txt',
    ):
        print('*' * 20, fname)
        try:
            datae = open(fname, 'rt', encoding='utf-8').read()
        except FileNotFoundError:
            print('no such file')
            continue
        datad = email.decrypt(datae, key)
        datad = datad.decode('utf-8')
        open(fname.replace('encrypted', 'decrypted'), 'wt', encoding='utf-8').write(datad)


main()
