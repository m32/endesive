#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive import pdf


def main():
    trusted_cert_pems = (
        # demo ca chain
        open("ca/demo2_ca.root.crt.pem", "rb").read(),
        # demo hsm ca chain
        #open("cert-hsm-ca.pem", "rb").read(),
    )
    for fname in (
        #"test-PDFXRef-signed-cms.pdf",
        #"test-PDFXRefStream-signed-cms.pdf",
        #"test-SHA256_RSA-signed-cms.pdf",
        #"pdf-acrobat.pdf",
        #"pdf-signed-cms-hsm-certum.pdf",
        #"pdf-signed-cms-hsm.pdf",

        "pdf-signed-cms.pdf",
        "pdf-signed-cms-hash.pdf",
        "pdf-signed-cms-ltv.pdf",
        "pdf-signed-cms-m32-actalis.pdf",
        "pdf-signed-cms-m32-unizeto.pdf",
        "pdf-signed-cms-pfx.pdf",
        "pdf-signed-cms-pil.pdf",
        "pdf-signed-cms-pypdf.pdf",
        "pdf-signed-cms-twice-1.pdf",
        "pdf-signed-cms-twice-2.pdf",
        "pdf-signed-cms-twice-end.pdf",
        "pdf-signed-fpdf.pdf",

        #"pdf-signed-java.pdf",
        #"pdf-signed-pypdf.pdf",
        #"pdf-encrypted-signed-java.pdf",
        #"pdf-encrypted-signed-pypdf.pdf",
        #"pdf-link-signed-java.pdf",
        #"pdf-link-signed-pypdf.pdf",
    ):
        print("*" * 20, fname)
        try:
            data = open(fname, "rb").read()
        except:
            print('skip')
            continue
        no = 0
        try:
            for (hashok, signatureok, certok) in pdf.verify(
                data, trusted_cert_pems
            ):
                print("*" * 10, "signature no:", no)
                print("signature ok?", signatureok)
                print("hash ok?", hashok)
                print("cert ok?", certok)
        except Exception as exc:
            print(exc)

main()
