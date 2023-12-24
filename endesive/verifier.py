# *-* coding: utf-8 *-*
import os
import glob
import hashlib

from asn1crypto import x509, core, pem, cms
from certvalidator import CertificateValidator, ValidationContext

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend


class VerifyData(object):
    def __init__(self, trustedCerts=None, systemCertsPath=None):
        certs = None
        if trustedCerts is not None:
            certs = []
            for cert_bytes in trustedCerts:
                # cert_bytes = cert_bytes.encode("utf8")
                if pem.detect(cert_bytes):
                    _, _, cert_bytes = pem.unarmor(cert_bytes)
                certs.append(x509.Certificate.load(cert_bytes))
        if systemCertsPath is not None:
            if not certs:
                certs = []
            for fname in glob.glob(os.path.join(systemCertsPath, "*.pem")):
                with open(fname, "rb") as fp:
                    cert_bytes = fp.read()
                if pem.detect(cert_bytes):
                    _, _, cert_bytes = pem.unarmor(cert_bytes)
                certs.append(x509.Certificate.load(cert_bytes))
        self.context = ValidationContext(certs)

    def verify(self, datas, datau):
        signed_data = cms.ContentInfo.load(datas)["content"]
        # signed_data.debug()

        signature = signed_data["signer_infos"][0]["signature"].native
        algo = signed_data["digest_algorithms"][0]["algorithm"].native
        attrs = signed_data["signer_infos"][0]["signed_attrs"]
        mdData = getattr(hashlib, algo)(datau).digest()
        if attrs is not None and not isinstance(attrs, core.Void):
            mdSigned = None
            for attr in attrs:
                if attr["type"].native == "message_digest":
                    mdSigned = attr["values"].native[0]
            signedData = attrs.dump()
            signedData = b"\x31" + signedData[1:]
        else:
            mdSigned = mdData
            signedData = datau
        hashok = mdData == mdSigned
        cert = None
        othercerts = []
        serial = signed_data["signer_infos"][0]["sid"].native["serial_number"]
        for pdfcert in signed_data["certificates"]:
            if serial != pdfcert.native["tbs_certificate"]["serial_number"]:
                othercerts.append(pdfcert.chosen)
            else:
                cert = pdfcert.chosen
        public_key = cx509.load_pem_x509_certificate(
            pem.armor("CERTIFICATE", cert.dump()), default_backend()
        ).public_key()

        sigalgo = signed_data["signer_infos"][0]["signature_algorithm"]
        # sigalgo.debug()
        sigalgoname = sigalgo.signature_algo
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            try:
                public_key.verify(
                    signature,
                    signedData,
                    ec.ECDSA(getattr(hashes, algo.upper())()),
                )
                signatureok = True
            except Exception as e:
                signatureok = False
        elif sigalgoname == "rsassa_pss":
            parameters = sigalgo["parameters"]
            # parameters.debug()
            # print(parameters.native)
            salgo = parameters["hash_algorithm"].native["algorithm"].upper()
            mgf = getattr(
                padding, parameters["mask_gen_algorithm"].native["algorithm"].upper()
            )(getattr(hashes, salgo)())
            salt_length = parameters["salt_length"].native
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PSS(mgf, salt_length),
                    getattr(hashes, salgo)(),
                )
                signatureok = True
            except:
                signatureok = False
        elif sigalgoname == "rsassa_pkcs1v15":
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PKCS1v15(),
                    getattr(hashes, algo.upper())(),
                )
                signatureok = True
            except:
                signatureok = False
        else:
            raise ValueError("Unknown signature algorithm")
        validator = CertificateValidator(
            cert, othercerts, validation_context=self.context
        )
        try:
            path = validator.validate_usage(set(["digital_signature"]))
            certok = True
        except Exception as ex:
            print("*" * 10, "failed certificate verification:", str(ex))
            print("cert.issuer:", cert.native["tbs_certificate"]["issuer"])
            print("cert.subject:", cert.native["tbs_certificate"]["subject"])
            certok = False
        return (hashok, signatureok, certok)


def verify(datas, datau, certs, systemCertsPath=None):
    cls = VerifyData(certs, systemCertsPath)
    return cls.verify(datas, datau)
