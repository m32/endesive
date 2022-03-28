# *-* coding: utf-8 *-*
import hashlib

from OpenSSL import crypto
from asn1crypto import x509, core, pem, cms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class VerifyData(object):

    def __init__(self, trustedCerts=None):
        self.store = crypto.X509Store()
        if trustedCerts is not None:
            for cert in trustedCerts:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
                self.add_cert(cert)

    def add_cert(self, trusted_cert):
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

    def verify(self, datas, datau):
        signed_data = cms.ContentInfo.load(datas)['content']
        # signed_data.debug()

        signature = signed_data['signer_infos'][0]['signature'].native
        algo = signed_data['digest_algorithms'][0]['algorithm'].native
        attrs = signed_data['signer_infos'][0]['signed_attrs']
        mdData = getattr(hashlib, algo)(datau).digest()
        if attrs is not None and not isinstance(attrs, core.Void):
            mdSigned = None
            for attr in attrs:
                if attr['type'].native == 'message_digest':
                    mdSigned = attr['values'].native[0]
            signedData = attrs.dump()
            signedData = b'\x31' + signedData[1:]
        else:
            mdSigned = mdData
            signedData = datau
        hashok = mdData == mdSigned
        serial = signed_data['signer_infos'][0]['sid'].native['serial_number']
        public_key = None
        for cert in signed_data['certificates']:
            if serial == cert.native['tbs_certificate']['serial_number']:
                cert = cert.dump()
                cert = pem.armor(u'CERTIFICATE', cert)
                public_key = crypto.load_certificate(crypto.FILETYPE_PEM, cert).get_pubkey().to_cryptography_key()
                break

        sigalgo = signed_data['signer_infos'][0]['signature_algorithm']
        # sigalgo.debug()
        sigalgoname = sigalgo.signature_algo
        if sigalgoname == 'rsassa_pss':
            parameters = sigalgo['parameters']
            #parameters.debug()
            #print(parameters.native)
            salgo = parameters['hash_algorithm'].native['algorithm'].upper()
            mgf = getattr(padding, parameters['mask_gen_algorithm'].native['algorithm'].upper())(getattr(hashes, salgo)())
            salt_length = parameters['salt_length'].native
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PSS(mgf, salt_length),
                    getattr(hashes, salgo)()
                )
                signatureok = True
            except:
                signatureok = False
        elif sigalgoname == 'rsassa_pkcs1v15':
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PKCS1v15(),
                    getattr(hashes, algo.upper())()
                )
                signatureok = True
            except:
                signatureok = False
        else:
            raise ValueError('Unknown signature algorithm')
        # TODO verify certificates
        certok = True
        for cert in signed_data['certificates']:
            scert = pem.armor(u'CERTIFICATE', cert.dump()).decode()
            if not self.verify_cert(scert):
                print('*' * 10, 'failed certificate verification')
                print('cert.issuer:', cert.native['tbs_certificate']['issuer'])
                print('cert.subject:', cert.native['tbs_certificate']['subject'])
                certok = False
        return (hashok, signatureok, certok)


def verify(datas, datau, certs):
    cls = VerifyData(certs)
    return cls.verify(datas, datau)
