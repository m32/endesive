#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import binascii
from OpenSSL.crypto import load_pkcs12
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from asn1crypto import x509, pem


def cert2asn(cert):
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def main():
    p12 = load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    signature = p12.get_privatekey().to_cryptography_key().sign(
        b"message",
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    cert = cert2asn(p12.get_certificate().to_cryptography())
    print('issuer', cert.issuer.native)
    print('subject', cert.subject.native)
main()
