#!/usr/bin/env vpython3
# coding: utf-8

import sys
from endesive import hsm, pdf
import PyKCS11 as PK11
from asn1crypto import pem as asn1pem

from hsm_config_softhsm import DLLPATH

class HSM(hsm.HSM):
    def main(self):
        cakeyID = bytes((0x1,))
        ca_cert_pem = asn1pem.armor('CERTIFICATE', self.cert_load(cakeyID))
        trusted_cert_pems = [ca_cert_pem]
        for fname in (
            "generated/pdf-signed-cms-hsm.pdf",
            "generated/pdf-signed-cms-hsm-signature_appearance.pdf",
            "generated/pdf-signed-cms-hsm-signature_manual.pdf",
        ):
            print('*' * 20, fname)
            try:
                data = open(fname, 'rb').read()
            except:
                print('skip')
                continue
            results = pdf.verify(data, trusted_cert_pems)
            for i in range(len(results)):
                print('*'*10, 'signature #{}'.format(i+1))
                (hashok, signatureok, certok) = results[i]
                print('signature ok?', signatureok)
                print('hash ok?', hashok)
                print('cert ok?', certok)

def main():
    cls = HSM(DLLPATH)
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()
main()
