#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from OpenSSL.crypto import load_pkcs12
from endesive import pdf

#import logging
#logging.basicConfig(level=logging.DEBUG)

def main():
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
    p12 = load_pkcs12(open('/devel/klient/m32/ssl/cert.p12', 'rb').read(), '1234')
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        p12.get_privatekey().to_cryptography_key(),
        p12.get_certificate().to_cryptography(),
        [],
        'sha256'
    )
    fname = fname.replace('.pdf', '-signed-cms-m32.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
