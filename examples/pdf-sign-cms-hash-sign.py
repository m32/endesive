import base64
import json
import sys

import PyKCS11 as PK11
from asn1crypto import pem as asn1pem

from endesive import hsm
from hsm_config_softhsm import DLLPATH


class Signer(hsm.HSM):
    def certificate(self):
        self.login("endesieve", "secret1")
        keyid = bytes((0x66, 0x66, 0x01))
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
    pdfname = 'generated/pdf.pdf'
    if len (sys.argv) > 1:
        pdfname = sys.argv[1]
    config = open(pdfname + ".json", "rt").read()
    config = json.loads(config)

    tosign = base64.decodebytes(config['tosign'].encode('ascii'))

    clshsm = Signer(DLLPATH)
    keyid, cert = clshsm.certificate()
    signed_bytes = clshsm.sign(keyid, tosign, "sha256")

    config['signed_bytes'] = b"".join(base64.encodebytes(signed_bytes).split()).decode('ascii')
    config['certificate'] = asn1pem.armor("CERTIFICATE", cert).decode('ascii')
    json.dump(config, open(pdfname + ".json", "wt"), indent=4)


main()
