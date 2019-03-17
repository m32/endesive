#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import pdf


def main():
    trusted_cert_pems = (open('demo2_ca.crt.pem', 'rt').read(),)
    for fname in (
            'pdf-signed-cms.pdf',
            'pdf-signed-fpdf.pdf',
            'test-PDFXRef-signed-cms.pdf',
            'test-PDFXRefStream-signed-cms.pdf'
    ):
        print('*' * 20, fname)
        try:
            data = open(fname, 'rb').read()
        except:
            continue
        (hashok, signatureok, certok) = pdf.verify(data, trusted_cert_pems)
        print('signature ok?', signatureok)
        print('hash ok?', hashok)
        print('cert ok?', certok)


main()
