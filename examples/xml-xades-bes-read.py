#!/usr/bin/env vpython3
# -*- coding: utf-8 -*-
import base64
import io
import zipfile

from lxml import etree


def XADESBesParser(xml):
    namespaces = {
        #        'dsig'  :"http://www.w3.org/2000/09/xmldsig#",
        #        'xsd'   :"http://www.w3.org/2001/XMLSchema",
        #        'soap'  :"http://www.w3.org/2003/05/soap-envelope",
    }

    tree = etree.parse(io.BytesIO(xml))
    namespaces.update(tree.getroot().nsmap)

    ns = [
        '/ds:Signature',
        '/ds:SignedInfo',
        '/ds:Reference',
    ]
    path = ''.join(ns)
    resp = tree.xpath(path, namespaces=namespaces)[0]
    ref = resp.get('URI')[1:]
    ns = [
        '/ds:Signature',
        '/ds:Object',
    ]
    path = ''.join(ns)
    for resp in tree.xpath(path, namespaces=namespaces):
        if ref == resp.get('Id'):
            text = resp.text
            if resp.get('Encoding') == 'http://www.w3.org/2000/09/xmldsig#base64':
                text = base64.decodebytes(text.encode('utf-8'))
                if resp.get('MimeType') == 'text/xml':
                    return text
            elif resp.get('MimeType') == 'text/xml':
                return etree.tostring(resp.getchildren()[0], encoding='UTF-8', xml_declaration=True, standalone=False)
                # return text
            zfp = zipfile.ZipFile(io.BytesIO(text), 'r', zipfile.ZIP_DEFLATED)
            return zfp.read(zfp.namelist()[0])
    return None


def main():
    document = XADESBesParser(open('xml-xades-bes-b64.xml', 'rb').read())
    open('xml-xades-bes-b64-read.xml', 'wb').write(document)
    document = XADESBesParser(open('xml-xades-bes-xml.xml', 'rb').read())
    open('xml-xades-bes-xml-read.xml', 'wb').write(document)


main()
