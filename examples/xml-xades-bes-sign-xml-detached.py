#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
from OpenSSL.crypto import load_pkcs12
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from endesive import xades, signer


def main():
    p12 = load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')

    def signproc(tosign, algosig):
        key = p12.get_privatekey().to_cryptography_key()
        signed_value_signature = key.sign(
            tosign,
            padding.PKCS1v15(),
            getattr(hashes, algosig.upper())()
        )
        return signed_value_signature

    data = open('xml.xml', 'rb').read()
    cert = p12.get_certificate().to_cryptography()
    certcontent = signer.cert2asn(cert).dump()

    cls = xades.BES()
    doc = cls.build('xml.xml', data, 'text/xml', cert, certcontent, signproc, False, False, True)
    data = etree.tostring(doc, encoding='UTF-8', xml_declaration=True, standalone=False)

    open('xml-xades-bes-detached.xml', 'wb').write(data)


if __name__ == '__main__':
    main()
