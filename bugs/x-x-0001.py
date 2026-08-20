from lxml import etree

def is_valid_svg(xml):
    parser = etree.XMLParser(resolve_entities=False)
    root = etree.fromstring(xml, parser=parser)
    xml = etree.tostring(
        signed_root, encoding="UTF-8", xml_declaration=True, standalone=False
    )
    print(xml)
    return root.tag.endswith('svg')

xml0 = b'''\
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>
  <concepto>&xxe;</concepto>
</svg>
'''


xml0 = b'''\
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % content SYSTEM "file:///etc/passwd">
	<!ENTITY % test '<!ENTITY &#x25; file SYSTEM "file:///tmp/%content;">'>
 	%test;
]>
'''
is_valid_svg(xml0)
