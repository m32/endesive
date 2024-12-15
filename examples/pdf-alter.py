import pymupdf
doc = pymupdf.open('pdf-acrobat.pdf')
page = doc[0]
rects = page.search_for("world")
page.add_highlight_annot(rects)
doc.save("pdf-acrobat-modified.pdf")
