#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from pypdf import PdfReader, PdfWriter

fname = "pdf.pdf"
with open(fname, "rb") as in_file:
    input_pdf = PdfReader(in_file)

    output_pdf = PdfWriter()
    output_pdf.append_pages_from_reader(input_pdf)
    output_pdf.encrypt("1234", "1234")

    fname = fname.replace('.pdf', '-encrypted.pdf')
    with open(fname, "wb") as out_file:
        output_pdf.write(out_file)
