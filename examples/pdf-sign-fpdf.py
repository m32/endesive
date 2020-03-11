#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive.pdf import pdf


def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': date,
        'reason': 'Dokument podpisany cyfrowo',
    }
    with open('demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    doc = pdf.FPDF()
    doc.pkcs11_setup(dct,
        p12[0], p12[1], p12[2],
        'sha256'
    )
    for i in range(2):
        doc.add_page()
        doc.set_font('helvetica', '', 13.0)
        doc.cell(w=75.0, h=22.0, align='C', txt='Hello, world page=%d.' % i, border=0, ln=0)
    doc.output('pdf-signed-fpdf.pdf', "F")


main()
