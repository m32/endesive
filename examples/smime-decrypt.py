#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.email import decrypt
from oscrypto import asymmetric

def main():
    key = asymmetric.load_private_key(open('demo2_user1.key.pem', 'rb').read(), '1234')
    datae = open('smime-encrypted.txt', 'rt', encoding='utf-8').read()
    datad = decrypt.decrypt(datae, key)
    datad = datad.decode('utf-8')
    open('smime-decrypted.txt', 'wt', encoding='utf-8').write(datad)

main()
