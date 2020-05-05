#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from optparse import OptionParser
from endesive.pdf import fpdf

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename", default="pdf.pdf",
                  help="write document to FILE", metavar="FILE")
parser.add_option("-l", "--link",
                  action="store_true", dest="link", default=False,
                  help="add link on page 1 to page 2")
parser.add_option("-t", "--ttf", dest="pdf_font", default="",
                  help="set ttf font for document")
parser.add_option("-v", "--pdf-version", dest="pdf_version", default="1.3",
                  help="set pdf vesion of generated document")

(options, args) = parser.parse_args()

doc = fpdf.FPDF()
doc.pdf_version = options.pdf_version
doc.set_compression(0)
font = 'helvetica'
if options.pdf_font:
    font = options.pdf_font.replace('\\', '/').split('/')[-1].split('.')[0]
    doc.add_font(font, '', options.pdf_font, True)

for i in range(2):
    doc.add_page()
    doc.set_font(font, '', 13.0)
    link = None
    if options.link and i == 0:
        link = doc.add_link()
        doc.set_link(link, page=2)
    doc.cell(w=75.0, h=22.0, align='C', txt='Hello, world page=%d.' % i, border=0, ln=2, link=link)
    if font != 'helvetica':
        doc.cell(w=75.0, h=22.0, align='C', txt='ąćęłńóśżź', border=0, ln=2)
doc.output(options.filename, "F")
