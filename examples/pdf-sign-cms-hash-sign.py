#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import base64
import json
from asn1crypto import pem as asn1pem
from endesive import hsm

import os
import sysconfig

os.environ["SOFTHSM2_CONF"] = "softhsm2.conf"
if not os.path.exists(os.path.join(os.getcwd(), "softhsm2.conf")):
    open("softhsm2.conf", "wt").write(
        """\
log.level = DEBUG
directories.tokendir = %s/softhsm2/
objectstore.backend = file
slots.removable = false
"""
        % os.getcwd()
    )
if not os.path.exists(os.path.join(os.getcwd(), "softhsm2")):
    os.mkdir(os.path.join(os.getcwd(), "softhsm2"))

#
#!/bin/bash
# SOFTHSM2_CONF=softhsm2.conf
# softhsm2-util --label "endesive" --slot 1 --init-token --pin secret1 --so-pin secret2
# softhsm2-util --show-slots
#

if sys.platform == "win32":
    dllpath = r"W:\binw\SoftHSM2\lib\softhsm2-x64.dll"
else:
    dllpath = os.path.join(sysconfig.get_config_var('LIBDIR'), "softhsm/libsofthsm2.so")

import PyKCS11 as PK11


class Signer(hsm.HSM):
    def certificate(self):
        self.login("endesieve", "secret1")
        keyid = bytes((0x66, 0x66, 0x90))
        try:
            pk11objects = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)]
            )
            all_attributes = [
                # PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                # PK11.CKA_ISSUER,
                # PK11.CKA_CERTIFICATE_CATEGORY,
                # PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes
                    )
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
            privKey = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyid)]
            )[0]
            mech = getattr(PK11, "CKM_%s_RSA_PKCS" % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()


def main():
    pdfname = 'pdf.pdf'
    if len (sys.argv) > 1:
        pdfname = sys.argv[1]
    config = open(pdfname + ".json", "rt").read()
    config = json.loads(config)

    tosign = base64.decodebytes(config['tosign'].encode('ascii'))

    clshsm = Signer(dllpath)
    keyid, cert = clshsm.certificate()
    signed_bytes = clshsm.sign(keyid, tosign, "sha256")

    config['signed_bytes'] = b"".join(base64.encodebytes(signed_bytes).split()).decode('ascii')
    config['certificate'] = asn1pem.armor("CERTIFICATE", cert).decode('ascii')
    json.dump(config, open(pdfname + ".json", "wt"), indent=4)


main()
