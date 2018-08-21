#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import fpdf

doc = fpdf.FPDF()
for i in range(2):
    doc.add_page()
    doc.set_font('helvetica', '', 13.0)
    doc.cell(w=75.0, h=22.0, align='C', txt='Hello, world page=%d.' % i, border=0, ln=0)
doc.output('pdf.pdf', "F")
