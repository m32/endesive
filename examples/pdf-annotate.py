#!/usr/bin/env vpython3
from pdf_annotate import PdfAnnotator, Location, Appearance

annotationtext = "some text"

a = PdfAnnotator("generated/pdf.pdf")
a.add_annotation(
    "text",
    Location(x1=50, y1=50, x2=200, y2=100, page=0),
    Appearance(
        fill=(0, 0, 0),
        stroke_width=1,
        wrap_text=True,
        font_size=12,
        content=annotationtext,
    ),
)
a.write("generated/pdf-annotate.pdf")
