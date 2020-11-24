#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from endesive import xades, signer, hsm

import os
import sys

os.environ["SOFTHSM2_CONF"] = "softhsm2.conf"
if sys.platform == "win32":
    dllpath = r"W:\binw\SoftHSM2\lib\softhsm2-x64.dll"
else:
    dllpath = "/usr/lib/softhsm/libsofthsm2.so"

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
    clshsm = Signer(dllpath)
    keyid, cert = clshsm.certificate()

    def signproc(tosign, algosig):
        return clshsm.sign(keyid, tosign, algosig)

    data = open("xml.xml", "rb").read()
    cert = x509.load_der_x509_certificate(cert, backend=default_backend())
    certcontent = cert.public_bytes(serialization.Encoding.DER)

    cls = xades.BES()
    doc = cls.enveloping(
        "dokument.xml",
        data,
        "application/xml",
        cert,
        certcontent,
        signproc,
        False,
        True,
    )
    data = etree.tostring(doc, encoding="UTF-8", xml_declaration=True, standalone=False)

    open("xml-hsm-softhsm2-enveloping.xml", "wb").write(data)


if __name__ == "__main__":
    main()
