#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
import signxml

cert = open("demo2_user1.crt.pem").read()
key = open("demo2_user1.key.pem").read()
data = open('xml.xml', 'rb').read()
root = etree.fromstring(data)
signed_root = signxml.XMLSigner(
    method=signxml.methods.enveloping
).sign(
    root,
    key=key,
    cert=cert,
    passphrase=b'1234'
)
verified_data = signxml.XMLVerifier(
).verify(
    signed_root,
    ca_pem_file="demo2_ca.crt.pem"
).signed_xml

xml = etree.tostring(
    signed_root,
    encoding='UTF-8',
    xml_declaration=True,
    standalone=False,
    pretty_print=True
)
open("xml-xmlsigner-enveloping.xml", "wb").write(xml)
