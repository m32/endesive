#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
import fpdf


def main():
    with open('ca/demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())

    pdf = fpdf.FPDF()
    for i in range(2):
        pdf.add_page()
        pdf.set_font('helvetica', '', 13.0)
        pdf.cell(w=75.0, h=22.0, align='C', text='Hello, world page=%d.' % i, border=0, new_x=fpdf.XPos.RIGHT, new_y=fpdf.YPos.TOP)
    pdf.sign(
        key=p12[0],
        cert=p12[1],
        extra_certs=p12[2],
        hashalgo="sha256",
        contact_info="mak@trisoft.com.pl",
        location="Szczecin",
        signing_time=datetime.datetime.now(datetime.UTC),
        reason="Dokument podpisany cyfrowo",
    )
    pdf.output('pdf-signed-fpdf.pdf')


main()
