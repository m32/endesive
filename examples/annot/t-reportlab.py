from io import BytesIO

from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

# Read the source PDF first so the overlay matches its page size.
reader = PdfReader("input.pdf")
first_page = reader.pages[0]
page_width = float(first_page.mediabox.width)
page_height = float(first_page.mediabox.height)

# Create a text overlay sized to the source page.
buffer = BytesIO()
c = canvas.Canvas(buffer, pagesize=(page_width, page_height))
c.setFont("Helvetica", 36)
c.setFillColorRGB(0.8, 0, 0)  # Red text
c.drawString(100, page_height - 100, "DRAFT — DO NOT DISTRIBUTE")
c.save()
buffer.seek(0)

# Merge overlay onto the first page.
overlay_reader = PdfReader(buffer)
writer = PdfWriter()

first_page.merge_page(overlay_reader.pages[0])
writer.add_page(first_page)

# Copy remaining pages unchanged.
for page in reader.pages[1:]:
    writer.add_page(page)

with open("output_stamped.pdf", "wb") as f:
    writer.write(f)

print("Overlay applied to first page.")
