#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import pprint
import binascii
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from asn1crypto import x509, pem


def cert2asn(cert_bytes):
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def main():
    if len(sys.argv) == 2:
        pemname = sys.argv[1]
    else:
        pemname = 'ca/demo2_ca.sub.crt.pem'
    data = open(pemname, 'rb').read()
    cert = cert2asn(data)
    pprint.pprint(cert.native)
main()
