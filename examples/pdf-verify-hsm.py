#!/usr/bin/env vpython3
# coding: utf-8

import os
import sys

os.environ['SOFTHSM2_CONF'] = 'softhsm2.conf'
if not os.path.exists(os.path.join(os.getcwd(), 'softhsm2.conf')):
    open('softhsm2.conf', 'wt').write('''\
log.level = DEBUG
directories.tokendir = %s/softhsm2/
objectstore.backend = file
slots.removable = false
''' % os.getcwd())
if not os.path.exists(os.path.join(os.getcwd(), 'softhsm2')):
    os.mkdir(os.path.join(os.getcwd(), 'softhsm2'))

#
#!/bin/bash
#SOFTHSM2_CONF=softhsm2.conf
#softhsm2-util --label "endesive" --slot 1 --init-token --pin secret1 --so-pin secret2
#softhsm2-util --show-slots
#

if sys.platform == 'win32':
    dllpath = r'W:\binw\SoftHSM2\lib\softhsm2-x64.dll'
else:
    dllpath = '/usr/lib/softhsm/libsofthsm2.so'

from endesive import hsm, pdf
import PyKCS11 as PK11
from asn1crypto import pem as asn1pem

'''
Create two certificates:
1. self signed CA certificate with serial equal to HSM keyID=0x01
2. USER 1 certificate with serial equal to HSM keyID=0x666690
'''
class HSM(hsm.HSM):
    def main(self):
        cakeyID = bytes((0x1,))
        ca_cert_pem = asn1pem.armor('CERTIFICATE', self.cert_load(cakeyID))
        trusted_cert_pems = (ca_cert_pem,)
        for fname in (
            'pdf-signed-cms-hsm.pdf',
        ):
            print('*' * 20, fname)
            try:
                data = open(fname, 'rb').read()
            except:
                continue
            (hashok, signatureok, certok) = pdf.verify(data, trusted_cert_pems)
            print('signature ok?', signatureok)
            print('hash ok?', hashok)
            print('cert ok?', certok)

def main():
    cls = HSM(dllpath)
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()
main()
