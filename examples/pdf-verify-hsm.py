import sys

import PyKCS11 as PK11
from asn1crypto import pem as asn1pem

from endesive import hsm, pdf
from hsm_config_softhsm import DLLPATH


class HSM(hsm.HSM):
    def main(self):
        cakeyID = bytes((0x1,))
        ca_cert_pem = asn1pem.armor("CERTIFICATE", self.cert_load(cakeyID))
        trusted_cert_pems = [ca_cert_pem]
        for fname in (
            "generated/pdf-signed-cms-hsm.pdf",
            "generated/pdf-signed-cms-hsm-signature_appearance.pdf",
            "generated/pdf-signed-cms-hsm-signature_manual.pdf",
        ):
            print("*" * 20, fname)
            try:
                data = open(fname, "rb").read()
            except:
                print("skip")
                continue
            result, more = pdf.verify(data, trusted_cert_pems)
            print("signature ok?", result.signatureok)
            print("hash ok?", result.hashok)
            print("cert ok?", result.certok)
            print("ocsp ok?", result.ocspok, "ocsp data:", result.ocspdata)
            print("tsp ok?", result.tspok, "tsp data:", result.tspdata)
            print("more?", more)


def main():
    cls = HSM(DLLPATH)
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()


main()
