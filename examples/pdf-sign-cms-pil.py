#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from PIL import Image
from endesive import pdf

#import logging
#logging.basicConfig(level=logging.DEBUG)

def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    img = Image.open('signature_test.png')
    dct = {
        b'sigflags': 3,
        # b'sigpage': 0,
        b'sigbutton': True,
        b'signature_img': img,
        b'contact': b'mak@trisoft.com.pl',
        b'location': b'Szczecin',
        b'signingdate': date.encode(),
        b'reason': b'Dokument podpisany cyfrowo',
        b'signature': b'Dokument podpisany cyfrowo',
        b'signaturebox': (470, 0, 570, 100),
    }
    with open('demo2_user1.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        p12[0],
        p12[1],
        p12[2],
        'sha256'
    )
    fname = fname.replace('.pdf', '-signed-cms-pil.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
