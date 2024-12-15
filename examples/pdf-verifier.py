#!/usr/bin/env python3
import sys
from endesive.pdf import PDFVerifier


def main():
    trustedcerts = []
    with open("nccert2016.crt", "rb") as fp:
        trustedcerts.append(fp.read())
    with open("ca/demo2_ca.crt.pem", "rb") as fp:
        trustedcerts.append(fp.read())

    if len(sys.argv) > 1:
        fname = sys.argv[1]
    else:
        fname = "pdf-signed-cms-m32-unizeto.pdf"
    with open(fname, "rb") as fp:
        pdf_data = fp.read()

    v = PDFVerifier(pdf_data, trustedcerts, "/etc/ssl/certs")

    if not v.is_valid_pdf():
        print(f"{fname} is not a pdf file")
        return

    if not v.is_signed():
        if v.modified:
            print(f"file {fname} is modified")
        else:
            print(f"file {fname} is unsigned")
        if not v.whole_file:
            print("the signature does not cover the entire pdf file")
        return
    
    (signed_data, tspdata, crldata, cert, othercerts, hashok, signatureok) = v.decompose_signature()
    if not hashok or not signatureok:
        print(f"file {fname} is modified")
        return

    certok = v.validate_certificate(cert, othercerts)
    if not certok:
        print(f"signing certificate is invalid")
        return

    print(f"signed with cert serial_number: {cert['tbs_certificate']['serial_number'].native}")
    print("other certificates:")
    for ocert in othercerts:
        print(f"     serial_number: {ocert['tbs_certificate']['serial_number'].native}")

    if crldata.native is not None:
        ok, info = v.verify_ocsp_data(cert, othercerts, crldata)
        if ok:
            print(f'ocsp issued at: {info[0]}, next check at: {info[1]}')

    if tspdata is not None:
        ok, info = v.verify_tsp_data(signed_data, tspdata, othercerts)
        print(f'tsp issued at: {info}')
        
if __name__ == '__main__':
    main()
