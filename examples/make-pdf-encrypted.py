#!/usr/bin/env python3
from pypdf import PdfReader, PdfWriter

fname = "generated/pdf.pdf"
with open(fname, "rb") as in_file:
    input_pdf = PdfReader(in_file)

    for algorithm in ["RC4-40", "RC4-128", "AES-128", "AES-256-R5", "AES-256"]:
        output_pdf = PdfWriter()
        output_pdf.append_pages_from_reader(input_pdf)
        output_pdf.encrypt("1234", owner_password="1234", algorithm=algorithm)

        ofname = fname.replace('.pdf', f'-encrypted-{algorithm}.pdf')
        with open(ofname, "wb") as out_file:
            output_pdf.write(out_file)
