#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import pdf

#import logging
#logging.basicConfig(level=logging.DEBUG)

def main():
    tspurl = "http://time.certum.pl"
    tspurl = "http://public-qlts.certum.pl/qts-17"
    date = datetime.datetime.utcnow() - datetime.timedelta()
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 44,
        'sigpage': 0,
        'sigbutton': True,
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': date.encode(),
        'reason': 'Dokument podpisany cyfrowo',
        'signature': 'Dokument podpisany cyfrowo',
        'signaturebox': (0, 0, 100, 100),
        'sigandcertify': True,
        'text': {
            'fontsize': 10,
        }
    }

    pk12fname = '/home/mak/Dokumenty/m32/ssl/unizeto1.p12'
    pk12pass = sys.argv[1].encode()
    with open(pk12fname, 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), pk12pass, backends.default_backend())

    ocspurl = 'https://ocsp.certum.pl/'
    ocspissuer = open('CertumDigitalIdentificationCASHA2.crt', 'rb').read()
    ocspissuer = x509.load_pem_x509_certificate(ocspissuer, backends.default_backend())

    fname = 'pdf.pdf'
    if len (sys.argv) > 2:
        fname = sys.argv[2]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        p12[0], p12[1], p12[2][:3],
        'sha256',
        None,
        tspurl,
        ocspurl=ocspurl,
        ocspissuer=ocspissuer
    )
    fname = fname.replace('.pdf', '-signed-cms-m32.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
