#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from lxml import etree
from oscrypto import asymmetric
from endesive.xades import bes

def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')

    def signproc(tosign):
        return asymmetric.rsa_pkcs1v15_sign(p12[0], tosign, 'sha1')

    data = open('xml.xml', 'rb').read()
    cert = p12[1].asn1
    certcontent = cert.dump()

    cls = bes.XADES()
    cls.build('dokument.xml', data, 'application/xml', cert, certcontent, signproc, False, True)
    data = etree.tostring(cls.root, encoding='UTF-8', xml_declaration=True, standalone=False)

    open('xml-xades-bes.xml', 'wb').write(data)


if __name__ == '__main__':
    main()
