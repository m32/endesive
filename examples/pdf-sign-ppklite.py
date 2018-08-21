#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
from endesive.pdf import ppklite
from oscrypto import asymmetric

def main():
    p12 = asymmetric.load_pkcs12(open('demo2_user1.p12', 'rb').read(), '1234')
    dct = {
        b'contact': b'mak@trisoft.com.pl',
        b'location': b'Szczecin',
        b'reason': b'Dokument podpisany cyfrowo',
        b'creationdate': b'20180727084119',
        b'modificationdate': b'20180731082642+02\'00\'',
        b'signingdate': b'20180731082642+02\'00\'',
        b'sigflags': 3,
    }
    datau = open('pdf.pdf', 'rb').read()
    datas = ppklite.sign(datau, dct, p12[0], p12[1], [], 'sha256', 'sha256')
    with open('pdf-signed-ppklite.pdf', 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

main()
