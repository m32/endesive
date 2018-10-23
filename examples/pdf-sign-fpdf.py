#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from OpenSSL.crypto import load_pkcs12
from endesive.pdf import pdf


def main():
    dct = {
        'sigflags': 3,
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': '20180731082642+02\'00\'',
        'reason': 'Dokument podpisany cyfrowo',
    }
    p12 = load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    doc = pdf.FPDF()
    doc.pkcs11_setup(dct,
        p12.get_privatekey().to_cryptography_key(),
        p12.get_certificate().to_cryptography(),
        [],
        'sha256'
    )
    for i in range(2):
        doc.add_page()
        doc.set_font('helvetica', '', 13.0)
        doc.cell(w=75.0, h=22.0, align='C', txt='Hello, world page=%d.' % i, border=0, ln=0)
    doc.output('pdf-signed-fpdf.pdf', "F")


main()
