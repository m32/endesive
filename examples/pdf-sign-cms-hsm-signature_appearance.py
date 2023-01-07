#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from endesive import pdf, hsm

import os
import sys
import datetime

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

import PyKCS11 as PK11

class Signer(hsm.HSM):
    def certificate(self):
        self.login("endesieve", "secret1")
        keyid = bytes((0x66,0x66,0x90))
        try:
            pk11objects = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                #PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                #PK11.CKA_ISSUER,
                #PK11.CKA_CERTIFICATE_CATEGORY,
                #PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(pk11object, all_attributes)
                except PK11.PyKCS11Error as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[PK11.CKA_VALUE])
                if keyid == bytes(attrDict[PK11.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login("endesieve", "secret1")
        try:
            privKey = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyid)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()

def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
    class User:
        full_name = 'u.full: ąćęłńóśżź'
        email = 'u.email: zażółcić gęślą jaźń'
        company = 'u.comp: ĄĆĘŁŃÓŚŻŹ'
        company_full_name = 'u.comp_full: ZAŻÓŁCIĆ GĘŚLĄ JAŹŃ'
    user = User()
    dct = {
        'aligned': 0,
        'sigflags': 3,
        'sigflagsft': 132,
        'sigpage': 0,
        'sigbutton': False,
        'sigfield': 'Signature-1667820612.078739',
        'auto_sigfield': False,
        'sigandcertify': False,
        'signaturebox': [175.79446979865773, 294.7236779911374, 447.47683221476507, 573.2810782865583],
        'contact': '',
        'location': '',
        'reason': '',
        'signingdate': "D:20221107123012+00'00'",
        'signature_appearance': {
            'background': [0.75, 0.8, 0.95],
            'outline': [0.2, 0.3, 0.5],
            'border': 1,
            'labels': True,
            'display': ['date']
        }
    }

    clshsm = Signer(dllpath)
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        None, None,
        [],
        'sha256',
        clshsm,
    )
    fname = fname.replace('.pdf', '-signed-cms-hsm-signature_appearance.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
