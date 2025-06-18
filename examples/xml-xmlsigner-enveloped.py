#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
import signxml

cert = open("ca/demo2_user1.crt.pem").read()
key = open("ca/demo2_user1.key.pem").read()
cert1 = open("ca/demo2_ca.sub.crt.pem").read()
data = open("xml.xml", "rb").read()

root = etree.fromstring(data)

signed_root = signxml.XMLSigner(method=signxml.methods.enveloped).sign(
    root, key=key, cert=[cert, cert1], passphrase=b"1234"
)

verified_data = (
    signxml.XMLVerifier().verify(signed_root, ca_pem_file="ca/demo2_ca.root.crt.pem").signed_xml
)

xml = etree.tostring(
    signed_root, encoding="UTF-8", xml_declaration=True, standalone=False
)
open("xml-xmlsigner-enveloped.xml", "wb").write(xml)

xml = etree.tostring(
    signed_root,
    encoding="UTF-8",
    xml_declaration=True,
    standalone=False,
    pretty_print=True,
)
open("xml-xmlsigner-enveloped1.xml", "wb").write(xml)
