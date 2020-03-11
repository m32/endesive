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
        b'sigflags': 3,
        b'sigpage': 0,
        b'sigbutton': True,
        b'contact': b'mak@trisoft.com.pl',
        b'location': b'Szczecin',
        b'signingdate': date.encode(),
        b'reason': b'Dokument podpisany cyfrowo',
        b'signature': b'Dokument podpisany cyfrowo',
        b'signaturebox': (0, 0, 100, 100),
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
