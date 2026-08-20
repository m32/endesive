import pymupdf

doc = pymupdf.open("input.pdf")
page = doc[0]

# Insert text at a specific position.
page.insert_text(
    (72, 72),  # x, y in points (1 inch from top-left)
    "Reviewed: 2026-02-27",
    fontsize=14,
    color=(0, 0, 0.8),  # Blue
)

doc.save("output_text.pdf")
doc.close()

print("Text inserted on first page.")
