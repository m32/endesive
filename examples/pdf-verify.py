#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import pdf


def main():
    trusted_cert_pems = (
        # certum chain
        open('ca-certum.pem', 'rt').read(),
        open('ca-ncc.pem', 'rt').read(),
        # actalis chain
        open('ca-actalis-cag1.pem', 'rt').read(),
        open('ca-actalis.pem', 'rt').read(),
        # demo ca chain
        open('demo2_ca.crt.pem', 'rt').read(),
        # demo hsm ca chain
        open('cert-hsm-ca.pem', 'rt').read(),
    )
    for fname in (
        'test-PDFXRef-signed-cms.pdf',
        'test-PDFXRefStream-signed-cms.pdf',
        'test-SHA256_RSA-signed-cms.pdf',
        'pdf-acrobat.pdf',
        'pdf-signed-cms-hsm-certum.pdf',
        'pdf-signed-cms-hsm.pdf',
        'pdf-signed-cms-m32.pdf',
        'pdf-signed-cms-oscrypto.pdf',
        'pdf-signed-cms-pfx.pdf',
        'pdf-signed-cms.pdf',
        'pdf-signed-fpdf.pdf',
        'pdf-signed-java.pdf',
        'pdf-signed-pypdf.pdf',
        'pdf-encrypted-signed-java.pdf',
        'pdf-encrypted-signed-pypdf.pdf',
        'pdf-link-signed-java.pdf',
        'pdf-link-signed-pypdf.pdf',
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
