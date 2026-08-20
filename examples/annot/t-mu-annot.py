import pymupdf

doc = pymupdf.open("input.pdf")
page = doc[0]

# Search for text and highlight it.
text_instances = page.search_for("important")
for inst in text_instances:
    page.add_highlight_annot(inst)

doc.save("output_highlighted.pdf")
doc.close()

print(f"Highlighted {len(text_instances)} instances.")
