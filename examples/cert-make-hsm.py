#!/usr/bin/env vpython3
# coding: utf-8

import os
import sys
import sysconfig

if "--force" in sys.argv:
    if os.path.exists(os.path.join(os.getcwd(), 'softhsm2')):
        import shutil
        shutil.rmtree(os.path.join(os.getcwd(), 'softhsm2'))

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
    dllpath = os.path.join(sysconfig.get_config_var('LIBDIR'), "softhsm/libsofthsm2.so")

from endesive import hsm
import PyKCS11 as PK11

'''
Create two certificates:
1. self signed hsm CA certificate with serial equal to HSM keyID=0x01
2. hsm USER 1 certificate with serial equal to HSM keyID=0x666690
'''
class HSM(hsm.HSM):
    def main(self):
        rootcakeyID = bytes((0x1,))
        rec = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, rootcakeyID)])
        if len(rec) == 0:
            label = 'hsm Root CA'
            self.gen_privkey(label, rootcakeyID)
            self.ca_gen(label, rootcakeyID, label)
        self.cert_export('cert-hsm-ca-root', rootcakeyID)

        cakeyID = bytes((0x2,))
        rec = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, cakeyID)])
        if len(rec) == 0:
            label = 'hsm Intermediate CA'
            self.gen_privkey(label, cakeyID)
            self.ca_sign(cakeyID, label, 2, label, 365 * 10, rootcakeyID)
        self.cert_export('cert-hsm-ca-sub', cakeyID)

        keyID = bytes((0x66,0x66,0x90))
        rec = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyID)])
        if len(rec) == 0:
            label = 'hsm USER 1'
            self.gen_privkey(label, keyID)
            self.ca_sign(keyID, label, 0x666690, "hsm USER 1", 365, cakeyID)
        self.cert_export('cert-hsm-user1', keyID)

def main():
    cls = HSM(dllpath)
    cls.create("endesieve", "secret1", "secret2")
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()
main()
