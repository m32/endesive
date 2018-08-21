#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.pdf import pdf
from oscrypto import asymmetric

def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    doc = pdf.FPDF()
    doc.pkcs11_setup(p12[0], p12[1], [], 'sha1', 'sha1')
    for i in range(2):
        doc.add_page()
        doc.set_font('helvetica', '', 13.0)
        doc.cell(w=75.0, h=22.0, align='C', txt='Hello, world page=%d.' % i, border=0, ln=0)
    doc.output('pdf-signed-fpdf.pdf', "F")
main()
