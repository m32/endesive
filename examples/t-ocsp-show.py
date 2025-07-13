#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from asn1crypto import ocsp as aocsp
from cryptography.x509 import ocsp
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import pkcs12


def main():
    print("*" * 20, "req")
    data = open("t-ocsp-req.bin", "rb").read()
    ocspr = aocsp.OCSPRequest.load(data)
    print(ocspr.debug())

    print("*" * 20, "resp")
    data = open("t-ocsp-resp.bin", "rb").read()
    ocspresp = aocsp.OCSPResponse.load(data)
    print(ocspresp.debug())


main()
