#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import binascii
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from asn1crypto import x509, pem


def cert2asn(cert):
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def main():
    with open('demo2_user1.p12', 'rb') as fp:
        p12pk, p12pc, p12oc = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    signature = p12pk.sign(
        b"message",
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    cert = cert2asn(p12pc)
    print('issuer', cert.issuer.native)
    print('subject', cert.subject.native)
main()
