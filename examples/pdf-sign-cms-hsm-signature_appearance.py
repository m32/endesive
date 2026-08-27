import datetime
import sys

import PyKCS11 as PK11

from endesive import hsm, pdf, signer
from hsm_config_softhsm import DLLPATH


class Signer(hsm.HSM):
    def certificate(self):
        self.login("endesieve", "secret1")
        keyid = bytes((0x66,0x66,0x01))
        try:
            pk11objects = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                #PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                #PK11.CKA_ISSUER,
                #PK11.CKA_CERTIFICATE_CATEGORY,
                #PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]

            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(pk11object, all_attributes)
                except PK11.PyKCS11Error as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                cert = bytes(attrDict[PK11.CKA_VALUE])
                if keyid == bytes(attrDict[PK11.CKA_ID]):
                    return keyid, cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login("endesieve", "secret1")
        try:
            privKey = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyid)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()

def main():
    date = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=12)
    date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
    class User:
        full_name = 'u.full: ąćęłńóśżź'
        email = 'u.email: zażółcić gęślą jaźń'
        company = 'u.comp: ĄĆĘŁŃÓŚŻŹ'
        company_full_name = 'u.comp_full: ZAŻÓŁCIĆ GĘŚLĄ JAŹŃ'
    user = User()
    dct = {
        'aligned': 0,
        'sigflags': 3,
        'sigflagsft': 132,
        'sigpage': 0,
        'sigbutton': False,
        'sigfield': 'Signature-1667820612.078739',
        'auto_sigfield': False,
        'sigandcertify': False,
        'signaturebox': [175.79446979865773, 294.7236779911374, 447.47683221476507, 573.2810782865583],
        'contact': '',
        'location': '',
        'reason': '',
        'signingdate': "D:20221107123012+00'00'",
        'signature_appearance': {
            'background': [0.75, 0.8, 0.95],
            'outline': [0.2, 0.3, 0.5],
            'border': 1,
            'labels': True,
            'display': ['date']
        }
    }

    othercerts = [
        signer.cert2asn(open('softhsm2/cert-hsm-ca-sub.pem', 'rb').read()),
    ]

    clshsm = Signer(DLLPATH)
    fname = 'generated/pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        None, None, othercerts,
        'sha256',
        clshsm,
    )
    fname = fname.replace('.pdf', '-signed-cms-hsm-signature_appearance.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()
