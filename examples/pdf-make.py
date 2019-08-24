#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.pdf import fpdf

doc = fpdf.FPDF()
doc.set_compression(0)
for i in range(2):
    doc.add_page()
    doc.set_font('helvetica', '', 13.0)
    doc.cell(w=75.0, h=22.0, align='C', txt='Hello, world page=%d.' % i, border=0, ln=0)
doc.output('pdf.pdf', "F")
