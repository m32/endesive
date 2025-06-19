# *-* coding: utf-8 *-*
import os
import glob
import hashlib
import datetime

from asn1crypto import x509, core, pem, cms

import certifi

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend


class VerifyData(object):
    def __init__(self, trustedCerts=None):
        with open(certifi.where(), "rb") as pems:
            certs = cx509.load_pem_x509_certificates(pems.read())
        if trustedCerts is not None:
            for cert_bytes in trustedCerts:
                certs.append(cx509.load_pem_x509_certificate(cert_bytes))
        #self.trustedCerts = trustedCerts
        store = Store(certs)
        self.verifier = PolicyBuilder(
            ).store(store
            ).time(datetime.datetime.utcnow()
            ).max_chain_depth(4
            ).build_client_verifier()

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
                othercerts.append(
                    cx509.load_pem_x509_certificate(
                        pem.armor("CERTIFICATE", pdfcert.chosen.dump())
                    )
                )
            else:
                assert cert is None
                cert = cx509.load_pem_x509_certificate(
                    pem.armor("CERTIFICATE", pdfcert.chosen.dump())
                )
        public_key = cert.public_key()

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

        try:
            self.verifier.verify(cert, othercerts)
            certok = True
        except Exception as ex:
            print("*" * 10, "failed certificate verification:", ex)
            print("cert.issuer:", cert.issuer)
            print("cert.subject:", cert.subject)
            certok = False
        return (hashok, signatureok, certok)


def verify(datas:bytes, datau:bytes, certs:list[x509.Certificate]=None) -> tuple[bool, bool, bool]:
    """
    Verify signed data.

    :param data: Email data as bytes.
    :param certs: List of additional certificates used to verify signature (system independent).
    :return:
        hashok, signatureok, certok

        hashok : bool
            True if the hash matches.
        signatureok : bool
            True if the signature is valid.
        certok : bool
            True if the certificate used for signing is trusted and valid.
    """
    cls = VerifyData(certs)
    return cls.verify(datas, datau)
