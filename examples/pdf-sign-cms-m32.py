#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import pdf

#import logging
#logging.basicConfig(level=logging.DEBUG)

def main():
    tspurl = "http://time.certum.pl"
    tspurl = "http://public-qlts.certum.pl/qts-17"
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        'sigpage': 0,
        'sigbutton': True,
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': date.encode(),
        'reason': 'Dokument podpisany cyfrowo',
        'signature': 'Dokument podpisany cyfrowo',
        'signaturebox': (0, 0, 100, 100),
        'text': {
            'fontsize': 10,
        }
    }
    with open('/home/mak/Dokumenty/m32/ssl/cert.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        p12[0], p12[1], p12[2],
        'sha256',
        None,
        tspurl,
    )
    fname = fname.replace('.pdf', '-signed-cms-m32.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
