#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.serialization import pkcs12

def get_from_cert(cert, what):
    try:
        aia = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access_description in aia.value:
            if access_description.access_method == what:
                return access_description.access_location.value
    except x509.ExtensionNotFound:
        return None
    return None

def get_crl_from_cert(cert):
    try:
        cdp = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        return cdp.value[0].full_name[0].value
    except x509.ExtensionNotFound:
        return None
    return None

def main():
    with open("ca/demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )

    ocspurl = 'http://ca.trisoft.com.pl/'

    ocspissuerurl = get_from_cert(p12[1], x509.OID_OCSP)
    rootcerturl = get_from_cert(p12[1], x509.OID_CA_ISSUERS)
    crlurl = get_crl_from_cert(p12[1])

    print('crlurl', crlurl)
    response = requests.get(crlurl)
    with open('t-ocsp-crl.der', 'wb') as fp:
        fp.write(response.content)

    print('ocspissuerurl', ocspissuerurl)
    response = requests.get(ocspissuerurl)
    ocspissuer = response.content
    with open('t-ocsp-issuer.der', 'wb') as fp:
        fp.write(ocspissuer)

    ocspissuer = x509.load_der_x509_certificate(ocspissuer, backends.default_backend())

    builder = ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(p12[1], ocspissuer, hashes.SHA1())
    req = builder.build()
    data = req.public_bytes(serialization.Encoding.DER)

    open("t-ocsp-req.bin", "wb").write(data)
    response = requests.post(
        ocspurl,
        headers={"Content-Type": "application/ocsp-request"},
        data=data,
    )
    open("t-ocsp-resp.bin", "wb").write(response.content)


main()
