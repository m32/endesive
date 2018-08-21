#!/usr/bin/env vpython3
import sys
import hashlib
from OpenSSL import crypto
from asn1crypto import x509, core, pem, util, cms, pdf
from oscrypto import asymmetric, keys

class Main:
    def __init__(self, cert):
        self.cert = cert

        # Create and fill a X509Sore with trusted certs
        trusted_cert_pems = (open('demo2_ca.crt.pem', 'rt').read(),)
        self.store = crypto.X509Store()
        for trusted_cert_pem in trusted_cert_pems:
            trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
            self.store.add_cert(trusted_cert)

    def verify_cert(self, cert_pem):
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(self.store, certificate)
        # Returns None if certificate can be validated
        try:
            result = store_ctx.verify_certificate()
        except:
            result = False
        return result is None

    def _load_cert(self, relative_path):
        with open(relative_path, 'rb') as f:
            cert_bytes = f.read()
            if pem.detect(cert_bytes):
                _, _, cert_bytes = pem.unarmor(cert_bytes)
            return x509.Certificate.load(cert_bytes)

    def verify(self, fname):
        pdfdata = open(fname, 'rb').read()
        n = pdfdata.find(b'/ByteRange')
        start = pdfdata.find(b'[', n)
        stop = pdfdata.find(b']', start)
        if n==-1 or start==-1 or stop==-1:
            print('unsigned dokument')
            return
        br = [int(i, 10) for i in pdfdata[start+1:stop].split()]
        print('br:', br)
        print (
            'data:',
            pdfdata[br[1]],
            pdfdata[br[2]-1],
        )
        contents = pdfdata[br[0]+br[1]+1:br[2]-1]
        data = []
        for i in range(0, len(contents), 2):
            data.append(int(contents[i:i+2], 16))
        bcontents = bytes(data)
        data1 = pdfdata[br[0]: br[0] + br[1]]
        data2 = pdfdata[br[2]: br[2] + br[3]]
        signedData = data1 + data2
        print (
            'len1:', len(data1), br[1], len(data1) == br[1],
            'len2:', len(data2), br[3], len(data2) == br[3],
        )
        #open(fname+'-part-1','wb').write(data1)
        #open(fname+'-part-2','wb').write(data2)
        #open(fname+'-tosign', 'wb').write(signedData)
        #open(fname+'-signature', 'wb').write(contents)

        signedInfo = cms.ContentInfo.load(bcontents)['content']
        #signedInfo.debug()
        algomd = signedInfo['digest_algorithms'].native[0]['algorithm']
        signature = signedInfo['signer_infos'][0].native['signature']
        algosig = signedInfo['signer_infos'][0].native['signature_algorithm']['algorithm']
        algosig = 'sha256'
        print('algomd:', algomd, 'algosig:', algosig)

        if 0:
            algosig = algomd#+'_rsa'
            algosig = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
            algosig = algosig[5]
            #data = signedInfo['encap_content_info']['content'].native
        attrs = signedInfo['signer_infos'][0]['signed_attrs']

        hashok = None
        if attrs is not None and not isinstance(attrs, core.Void):
            mdSigned = None
            for attr in attrs:
                if attr['type'].native == 'message_digest':
                    mdSigned = attr['values'].native[0]
            mdData = getattr(hashlib, algomd)()
            mdData.update(data1)
            mdData.update(data2)
            mdData = mdData.digest()
            hashok = mdData == mdSigned

            signedData = attrs.dump()
            signedData = b'\x31'+signedData[1:]
        print('algo:', algomd, ', ok?', hashok)

        public_key = asymmetric.load_public_key(open(self.cert, 'rb').read())
        try:
            asymmetric.rsa_pkcs1v15_verify(public_key, signature, signedData, algosig)
            result = True
        except:
            result = False
            import traceback; traceback.print_exc()
        print('sign:', algosig, ', ok?', result)

        #attrs.debug()
        attrs = attrs.native
        #del attrs[3]
        #print attrs

        # TODO verify certificates
        ok = True
        for cert in signedInfo['certificates']:
            scert = pem.armor(u'CERTIFICATE', cert.dump()).decode()
            if not self.verify_cert(scert):
                print('*'*10, 'failed certificate verification')
                print('cert.issuer:', cert.native['tbs_certificate']['issuer'])
                print('cert.subject:', cert.native['tbs_certificate']['subject'])
                ok = False
        print('cert ok?', ok)

def main():
    cls = Main('demo2_user1.crt.pem')
    for fname in (
        'pdf-signed-cms.pdf',
        'pdf-signed-cades.pdf',
        'pdf-signed-ppklite.pdf',
    ):
        print('*'*20, fname)
        cls.verify(fname)

main()
