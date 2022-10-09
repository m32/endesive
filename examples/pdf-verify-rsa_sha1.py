#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import hashlib
from endesive.pdf.PyPDF2 import PdfFileReader
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    fname = "pdf-adobe-webcapture-x509.rsa_sha1.pdf"
    pdf = PdfFileReader(fname)
    catalog = pdf.trailer["/Root"]
    docmdp = catalog["/Perms"]["/DocMDP"]
    if 0:
        print(catalog)
        for k, v in catalog.items():
            print(k, "=", v)
    if 0:
        print(docmdp)
        for k, v in docmdp.items():
            print(k, "=", v)
    dtype = docmdp["/Type"]
    dcert = docmdp["/Cert"]
    dbyterange = docmdp["/ByteRange"]
    dcontents = docmdp["/Contents"]
    dfilter = docmdp["/Filter"]
    dsubfilter = docmdp["/SubFilter"]
    dmethod = docmdp["/Reference"][0]["/DigestMethod"]

    try:
        dl = docmdp["/Reference"][0]["/DigestLocation"]
        dv = docmdp["/Reference"][0]["/DigestValue"]
    except:
        dl = [0, 0]
        dv = 'aa'
    assert dl[0] == 0 and dl[1] == 0 and dv == 'aa'

    print(dfilter, dsubfilter, dmethod, dbyterange)
    assert dfilter == '/Adobe.PPKLite'
    assert dsubfilter == '/adbe.x509.rsa_sha1'
    assert dmethod == '/MD5'
    del pdf

    data = open(fname, "rb").read()
    data1 = data[dbyterange[0] : dbyterange[1]]
    data2 = data[dbyterange[2] : dbyterange[2] + dbyterange[3]]
    if 1:
        data = data1 + data2
    else:
        # dirty games with dl and dv ?
        dig = hashlib.md5()
        dig.update(data1)
        if data2:
            dig.update(data2)
        data = dig.digest()
    if 0:
        open("a-cert.der", "wb").write(dcert)
        open("a-sig.der", "wb").write(signature)
        open("a-data-1.der", "wb").write(data1)
        open("a-data-2.der", "wb").write(data2)

    cert = x509.load_der_x509_certificate(dcert, default_backend())
    signature = dcontents[3:] # ASN1 STRING
    pubkey = cert.public_key()
    try:
        pubkey.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
        print('signature ok')
    except InvalidSignature:
        print('invalid signature')

main()
