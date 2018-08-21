#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.pdf import cms
from oscrypto import asymmetric

def main():
    dct = {
        b'sigflags': 3,
        b'contact': b'mak@trisoft.com.pl',
        b'location': b'Szczecin',
        b'signingdate': b'20180731082642+02\'00\'',
        b'reason': b'Dokument podpisany cyfrowo',
    }
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    datau = open('pdf.pdf', 'rb').read()
    datas = cms.sign(datau, dct, p12[0], p12[1], [], 'sha256', 'sha256')
    with open('pdf-signed-cms.pdf', 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

main()
