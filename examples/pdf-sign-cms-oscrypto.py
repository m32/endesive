#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from oscrypto import keys, asymmetric
from endesive import hsm, pdf

#import logging
#logging.basicConfig(level=logging.DEBUG)

class OscryptoHSM(hsm.BaseHSM):
    def __init__(self, key, cert, certs, pss):
        self.key = key
        self.cert = cert
        self.certs = certs
        self.pss = pss

    def certificate(self):
        return 1, self.cert

    def sign(self, keyid, tosign, mech):
        key = asymmetric.load_private_key(self.key)
        if self.pss:
            signed_value_signature = asymmetric.rsa_pss_sign(key, tosign, mech.lower())
        else:
            signed_value_signature = asymmetric.rsa_pkcs1v15_sign(
                key, tosign, mech.lower()
            )
        return signed_value_signature

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
    with open('ca/demo2_user1.p12', 'rb') as f:
        key, cert, certe = keys.parse_pkcs12(f.read(), b'1234')

    if len (sys.argv) > 1:
        fname = sys.argv[1]
    else:
        fname = 'pdf.pdf'

    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        None,
        cert,
        certe,
        'sha256',
        hsm=OscryptoHSM(key, cert, certe, False),
    )

    fname = fname.replace('.pdf', '-signed-cms-oscrypto.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
