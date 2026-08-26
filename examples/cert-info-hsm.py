import pprint

import PyKCS11 as PK11

from endesive import hsm, pdf
from hsm_config_softhsm import DLLPATH


class Signer(hsm.HSM):
    def certificate(self):
        self.login("endesieve", "secret1")
        keyid = bytes((0x66,0x66,0x01))
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

import binascii

from asn1crypto import pem, x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12


def cert2asn(cert, cert_bytes=True):
    if isinstance(cert, x509.Certificate):
        return cert
    if cert_bytes:
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    else:
        cert_bytes = cert
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def main():
    hsm = Signer(DLLPATH)
    hsm.login("endesieve", "secret1")
    keyid = bytes((0x66,0x66,0x01))
    ic = hsm.cert_load(keyid)
    hsm.logout()
    if ic is None:
        print(f'cert for key: {[hex(int(i)) for i in keyid]} not found')
    else:
        ic = cert2asn(ic, False)
        print('cert:')
        pprint.pprint(ic.native)
main()
