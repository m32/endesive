#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
from oscrypto import asymmetric

from endesive import xades


def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')

    def signproc(tosign, algosig):
        return asymmetric.rsa_pkcs1v15_sign(p12[0], tosign, algosig)

    data = open('xml.xml', 'rb').read()
    cert = p12[1].asn1
    certcontent = cert.dump()

    cls = xades.BES()
    cls.build('dokument.xml', data, 'text/xml', cert, certcontent, signproc, True, True)
    data = etree.tostring(cls.root, encoding='UTF-8', xml_declaration=True, standalone=False)

    open('xml-xades-bes-b64.xml', 'wb').write(data)


if __name__ == '__main__':
    main()
