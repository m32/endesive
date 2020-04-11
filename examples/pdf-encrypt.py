#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from PyPDF2 import PdfFileReader, PdfFileWriter

fname = "pdf.pdf"
with open(fname, "rb") as in_file:
    input_pdf = PdfFileReader(in_file)

    output_pdf = PdfFileWriter()
    output_pdf.appendPagesFromReader(input_pdf)
    output_pdf.encrypt("1234", "1234")

    fname = fname.replace('.pdf', '-encrypted.pdf')
    with open(fname, "wb") as out_file:
        output_pdf.write(out_file)
