#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import io
from OpenSSL import crypto
from endesive import email


def main():
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, open('demo2_user1.key.pem', 'rb').read(), b'1234')
    key = key.to_cryptography_key()
    for fname in (
            'smime-ssl-encrypted.txt',
            'smime-encrypted.txt',
            'smime-ssl-oaep-encrypted.txt',
    ):
        print('*' * 20, fname)
        try:
            datae = io.open(fname, 'rt', encoding='utf-8').read()
        except:
            print('no such file')
            continue
        datad = email.decrypt(datae, key)
        datad = datad.decode('utf-8')
        io.open(fname.replace('encrypted', 'decrypted'), 'wt', encoding='utf-8').write(datad)


main()
