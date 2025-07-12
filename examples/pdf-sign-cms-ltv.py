#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509

from endesive.pdf import cms


def main():
    date = datetime.datetime.now()
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 16384,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        # "sigbutton": True,
        # "sigfield": "Signature1",
        # "auto_sigfield": True,
        # "sigandcertify": True,
        # "signaturebox": (470, 840, 570, 640),
        "signature": "Dokument podpisany cyfrowo ąćęłńóśżź",
        # "signature_img": "signature_test.png",
        "contact": "contact:mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
        'tsa_url': 'http://timestamp.digicert.com',
        "ltv": True,
    }
    with open("ca/demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )
    fname = "pdf.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()

    print(f"Signing certificate subject: {p12[1].subject.rfc4514_string()}")
    print(f"Signing certificate issuer: {p12[1].issuer.rfc4514_string()}")
    print(f"Additional certificates in chain: {len(p12[2]) if p12[2] else 0}")

    issuer_cert = None
    if p12[2]:
        issuer_cert = p12[2][0]
        print(
            f"Using issuer certificate: {issuer_cert.subject.rfc4514_string()}")
    else:
        print("No additional certificates found in P12 file")

    # ocsp_url = "http://ca.trisoft.com.pl/ocsp"

    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256",
                    #  ocspurl=ocsp_url,
                     ocspissuer=issuer_cert,
                     timestampurl=dct['tsa_url'])
    fname = fname.replace(".pdf", "-signed-cms.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
