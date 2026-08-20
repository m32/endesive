import pymupdf

doc = pymupdf.open("input.pdf")
page = doc[0]

# Define a rectangle where the image should appear.
rect = pymupdf.Rect(400, 20, 550, 80)  # x0, y0, x1, y1
page.insert_image(rect, filename="logo.png")

doc.save("output_logo.pdf")
doc.close()

print("Image inserted on first page.")
