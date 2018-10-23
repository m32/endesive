#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
from OpenSSL.crypto import load_pkcs12
from endesive import pdf


def main():
    dct = {
        b'sigflags': 3,
        b'contact': b'mak@trisoft.com.pl',
        b'location': b'Szczecin',
        b'signingdate': b'20180731082642+02\'00\'',
        b'reason': b'Dokument podpisany cyfrowo',
    }
    p12 = load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('pdf.pdf', 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        p12.get_privatekey().to_cryptography_key(),
        p12.get_certificate().to_cryptography(),
        [],
        'sha256'
    )
    with open('pdf-signed-cms.pdf', 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
