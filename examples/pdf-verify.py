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
        #"generated/test-PDFXRef-signed-cms.pdf",
        #"generated/test-PDFXRefStream-signed-cms.pdf",
        #"generated/test-SHA256_RSA-signed-cms.pdf",
        #"generated/pdf-acrobat.pdf",
        #"generated/pdf-signed-cms-hsm-certum.pdf",
        #"generated/pdf-signed-cms-hsm.pdf",

        "generated/pdf-encrypted-AES-128-signed-cms.pdf",
        "generated/pdf-encrypted-AES-256-signed-cms.pdf",
        "generated/pdf-encrypted-AES-256-signed-cms.pdf",
        "generated/pdf-encrypted-RC4-128-signed-cms.pdf",
        "generated/pdf-encrypted-RC4-40-signed-cms.pdf",
        "generated/pdf-qpdf-signed-cms.pdf",
        #
        "generated/pdf-signed-cms.pdf",
        "generated/pdf-signed-cms-hash.pdf",
        "generated/pdf-signed-cms-m32-actalis.pdf",
        "generated/pdf-signed-cms-m32-unizeto.pdf",
        "generated/pdf-signed-cms-pfx.pdf",
        "generated/pdf-signed-cms-pil.pdf",
        "generated/pdf-signed-cms-twice-1.pdf",
        "generated/pdf-signed-cms-twice-2.pdf",
        "generated/pdf-signed-cms-twice-end.pdf",
        "generated/pdf-signed-fpdf.pdf",

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
                no += 1
        except Exception as exc:
            print(exc)
            import traceback
            traceback.print_exc()

main()
