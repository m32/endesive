#!/usr/bin/env vpython2
# -*- coding: utf-8 -*-
import base64
import zipfile
import io
from lxml import etree

def XADESParser(xml):
    namespaces={
        #'dsig'  :"http://www.w3.org/2000/09/xmldsig#",
        #'xsd'   :"http://www.w3.org/2001/XMLSchema",
        #'soap'  :"http://www.w3.org/2003/05/soap-envelope",
    }

    tree = etree.parse(io.BytesIO(xml))
    namespaces.update(tree.getroot().nsmap)

    # del namespaces[None]
    ns = [
        '/ds:Signature',
        '/ds:SignedInfo',
        '/ds:Reference',
    ]
    path = ''.join(ns)
    resp = tree.xpath( path, namespaces=namespaces )[0]
    ref = resp.get('URI')[1:]
    ns = [
        '/ds:Signature',
        '/ds:Object',
        ]
    path = ''.join(ns)
    for xobj in tree.xpath( path, namespaces=namespaces ):
        if ref == xobj.get('Id'):
            if xobj.get('MimeType').split('/')[1] == 'xml':
                dokument = xobj.text
                dokument = base64.decodestring(dokument)
                return dokument
            else:
                dokument = xobj.text
                dokument = base64.decodestring(dokument)
                zfp = zipfile.ZipFile(io.BytesIO(dokument), 'r', zipfile.ZIP_DEFLATED)
                return zfp.read(zfp.namelist()[0])

def main():
    data = open('xml-xades-bes.xml', 'rb').read()
    data = XADESParser(data)
    print data

main()

