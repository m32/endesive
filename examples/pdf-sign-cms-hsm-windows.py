import sys
import datetime
from win32 import win32crypt
from win32.lib import win32cryptcon

from endesive import hsm, pdf

CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x10000

class WindowsHSM(hsm.BaseHSM):
    def __init__(self, subject, certstore='MY'):
        self.derdata = None
        self.cert = None

        st = win32crypt.CertOpenSystemStore(certstore, None)
        try:
            certs = st.CertEnumCertificatesInStore()
            for cert in certs:
                if win32crypt.CertNameToStr(cert.Subject) == subject:
                    self.derdata = cert.CertEncoded
                    self.cert = cert
                    break
        finally:
            st.CertCloseStore()

    def certificate(self):
        return 1, self.derdata

    def sign(self, keyid, data, mech):
        keyspec, cryptprov = self.cert.CryptAcquireCertificatePrivateKey(
            win32cryptcon.CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG
        )
        chash = cryptprov.CryptCreateHash(win32cryptcon.CALG_SHA1, None, 0)
        chash.CryptHashData(data, 0)
        res = chash.CryptSignHash(keyspec, 0)
        return res[::-1]

def main():
    clshsm = WindowsHSM('USER 1')

    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        'contact': 'user@example.com',
        'location': 'England',
        'signingdate': date.encode(),
        'reason': 'Test',
    }
    fname = 'pdf.pdf'
    if len (sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        None, None,
        [],
        'sha1',
        clshsm,
    )
    fname = fname.replace('.pdf', '-signed-cms-hsm-windows.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

main()
