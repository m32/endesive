#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from lxml import etree
import signxml

if sys.argv[1:]:
    fname = sys.argv[1]
else:
    fname = "xml-xmlsigner-enveloped.xml"
    #fname = "xml-xmlsigner-enveloping.xml"
    #fname = 'xml-xades-bes-enveloped.xml'
data = open(fname, "rb").read()
signed_root = etree.fromstring(data)
verified_data = (
    signxml.XMLVerifier().verify(signed_root, ca_pem_file="demo2_ca.crt.pem").signed_xml
)

xml = etree.tostring(
    verified_data,
    encoding="UTF-8",
    xml_declaration=True,
    standalone=False,
    pretty_print=True,
)
# open(fname.replace('.xml', '-result.xml'), "wb").write(xml)
