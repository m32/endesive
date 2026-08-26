import io

from endesive import email


def main():
    trusted_cert_pems = (open('ca/demo2_ca.root.crt.pem', 'rb').read(),)

    for fname in (
        'generated/smime-signed-attr.txt',
        'generated/smime-signed-attr-custom.txt',
        'generated/smime-signed-hsm.txt',
        'generated/smime-signed-noattr.txt',
        'generated/smime-signed-pss.txt',
        'generated/smime-ssl-pss-signed.txt',
        'generated/smime-ssl-signed-attr.txt',
        'generated/smime-ssl-signed-noattr.txt',
    ):
        print('*' * 20, fname)
        try:
            datae = io.open(fname, 'rt', encoding='utf-8').read()
        except:
            print('no such file')
            continue
        result = email.verify(datae, trusted_cert_pems)
        print("signature ok?", result.signatureok)
        print("hash ok?", result.hashok)
        print("cert ok?", result.certok)
        print("ocsp ok?", result.ocspok, "ocsp data:", result.ocspdata)
        print("tsp ok?", result.tspok, "tsp data:", result.tspdata)


main()
