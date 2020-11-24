#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from endesive import xades, signer, hsm

import os
import sys

if sys.platform == "win32":
    dllpath = r"c:\windows\system32\cryptoCertum3PKCS.dll"
else:
    dllpath = "/devel/bin/proCertumSmartSign-8.1.15/libcryptoCertum3PKCS.so"

import PyKCS11 as PK11


class Signer(hsm.HSM):
    def certificate(self):
        self.login("profil bezpieczny", "9593")
        keyid = [
            0x5E,
            0x9A,
            0x33,
            0x44,
            0x8B,
            0xC3,
            0xA1,
            0x35,
            0x33,
            0xC7,
            0xC2,
            0x02,
            0xF6,
            0x9B,
            0xDE,
            0x55,
            0xFE,
            0x83,
            0x7B,
            0xDE,
        ]
        # keyid = [0x3f, 0xa6, 0x63, 0xdb, 0x75, 0x97, 0x5d, 0xa6, 0xb0, 0x32, 0xef, 0x2d, 0xdc, 0xc4, 0x8d, 0xe8]
        keyid = bytes(keyid)
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
        self.login("profil bezpieczny", "9593")
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

    for tspurl, tspcred in (
        (None, None),
        ("http://public-qlts.certum.pl/qts-17", None)
    ):
        cls = xades.BES()
        doc = cls.enveloping(
            "dokument.xml",
            data,
            "application/xml",
            cert,
            certcontent,
            signproc,
            False,
            False,
            False,
            tspurl,
            tspcred,
        )
        data = etree.tostring(doc, encoding="UTF-8", xml_declaration=True, standalone=False)
        if tspurl is None:
            open("xml-hsm-certum-enveloping.xml", "wb").write(data)
        else:
            open("xml-hsm-certum-enveloping-t.xml", "wb").write(data)


if __name__ == "__main__":
    main()
