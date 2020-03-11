#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import xades, signer


def main():
    with open('demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())

    def signproc(tosign, algosig):
        key = p12[0]
        signed_value_signature = key.sign(
            tosign,
            padding.PKCS1v15(),
            getattr(hashes, algosig.upper())()
        )
        return signed_value_signature

    data = open('xml.xml', 'rb').read()
    cert = p12[1]
    certcontent = signer.cert2asn(cert).dump()

    cls = xades.BES()
    doc = cls.build('xml.xml', data, 'text/xml', cert, certcontent, signproc, False, False, True)
    data = etree.tostring(doc, encoding='UTF-8', xml_declaration=True, standalone=False)

    open('xml-xades-bes-detached.xml', 'wb').write(data)


if __name__ == '__main__':
    main()
