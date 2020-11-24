#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from oscrypto import keys
from endesive import pdf

#import logging
#logging.basicConfig(level=logging.DEBUG)

def main():
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        # 'sigpage': 0,
        'sigbutton': True,
        'signature_img': 'signature_test.png',
        'contact': 'mak@trisoft.com.pl',
        'location': 'Szczecin',
        'signingdate': date.encode(),
        'reason': 'Dokument podpisany cyfrowo',
        'signature': 'Dokument podpisany cyfrowo',
        'signaturebox': (470, 0, 570, 100),
    }
    with open('demo2_user1.p12', 'rb') as f:
        key, cert, certe = keys.parse_pkcs12(f.read(), b'1234')
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        key,
        cert,
        certe,
        'sha256'
    )
    fname = fname.replace('.pdf', '-signed-cms-oscrypto.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
