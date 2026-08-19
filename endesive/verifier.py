# *-* coding: utf-8 *-*
import hashlib
import datetime
import warnings
import logging

from asn1crypto import x509, core, pem, cms

import certifi

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger(__name__)


class SignatureVerifier(object):
    def __init__(self, trustedCerts=None):
        with open(certifi.where(), "rb") as pems:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="Parsed a serial number")
                certs = cx509.load_pem_x509_certificates(pems.read())
        if trustedCerts is not None:
            for cert_bytes in trustedCerts:
                certs.append(cx509.load_pem_x509_certificate(cert_bytes, backend=default_backend()))
        store = Store(certs)
        self.verifier = PolicyBuilder(
            ).store(store
            ).time(datetime.datetime.now(datetime.UTC)
            ).max_chain_depth(4
            ).build_client_verifier()

    def _validator_cb(self, policy, cert, ext):
        print('*'*20, 'validator_cb')
        print('pol:', policy)
        print('cert:', cert)
        print('ext:', ext)
        # Any exception from the python validator is treated as failure.
        #raise ValueError("...")

    def _resolve_hash_cls(self, algo_name):
        if algo_name is None:
            hashcls = None
        else:
            normalized = algo_name.upper().replace("-", "")
            if normalized.endswith("RSA"):
                normalized = normalized[:-3].rstrip("_")
            hashcls = getattr(hashes, normalized)
        if hashcls is None:
            raise ValueError(f"Invalid hash algorithm: {algo_name}")
        return hashcls

    def validate_certificate(self, cert, othercerts=[]) -> bool:
        try:
            self.verifier.verify(cert, othercerts)
            certok = True
        except Exception as ex:
            logger.exception(ex)
            certok = False
        return certok

    def _verify_ocsp_cert_id(self, cert_id, issuer_cert):
        hash_name = cert_id["hash_algorithm"]["algorithm"].native
        hash_cls = self._resolve_hash_cls(hash_name)

        issuer_asn1 = x509.Certificate.load(
            issuer_cert.public_bytes(serialization.Encoding.DER)
        )
        issuer_name = issuer_asn1["tbs_certificate"]["subject"].dump()
        issuer_key_bitstring = issuer_asn1["tbs_certificate"]["subject_public_key_info"]["public_key"]
        issuer_key = issuer_key_bitstring.contents[1:]

        digest = hashes.Hash(hash_cls())
        digest.update(issuer_name)
        expected_name_hash = digest.finalize()

        digest = hashes.Hash(hash_cls())
        digest.update(issuer_key)
        expected_key_hash = digest.finalize()

        return (
            cert_id["issuer_name_hash"].native == expected_name_hash
            and cert_id["issuer_key_hash"].native == expected_key_hash
        )

    def decompose_signed_data(self, signaturebytes: bytes, datau: bytes) -> tuple:
        # return (signed_data, tspdata, crls, cert, othercerts, hashok, signatureok)
        signed_data = cms.ContentInfo.load(signaturebytes)["content"]

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
                if cert is not None:
                    raise ValueError("Multiple signer certificates with the same serial")
                cert = cx509.load_pem_x509_certificate(
                    pem.armor("CERTIFICATE", pdfcert.chosen.dump())
                )
        if cert is None:
            raise ValueError("Signer certificate not found in signed data")
        public_key = cert.public_key()

        sigalgo = signed_data["signer_infos"][0]["signature_algorithm"]
        sigalgoname = sigalgo.signature_algo
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            try:
                public_key.verify(
                    signature,
                    signedData,
                    ec.ECDSA(getattr(hashes, algo.upper())()),
                )
                signatureok = True
            except Exception as exc:
                logger.exception("Signature verification failed:", exc_info=exc)
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
            except Exception as exc:
                logger.exception("Signature verification failed:", exc_info=exc)
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
            except Exception as exc:
                logger.exception("Signature verification failed:", exc_info=exc)
                signatureok = False
        else:
            raise ValueError("Unknown signature algorithm")

        tspdata = None
        for attr in signed_data["signer_infos"][0]["unsigned_attrs"]:
            if attr["type"].native == "signature_time_stamp_token":
                for v in attr["values"]:
                    if v["content_type"].native == "signed_data":
                        tspdata = v["content"]
        crls = signed_data["crls"]

        #print(signed_data, tspdata, crls, cert, othercerts, hashok, signatureok)
        return (signed_data, tspdata, crls, cert, othercerts, hashok, signatureok)

    def verify_ocsp_data(self, cert, othercerts, crldata):
        issuer_cert = next((item for item in othercerts if item.subject == cert.issuer), None)
        if issuer_cert is None:
            logger.debug("cannot resolve issuer certificate for OCSP CertID check")
            return False, None

        for crl1 in crldata:
            # clr1: cms.RevocationInfoChoice
            if crl1.native["other_rev_info_format"] != "ocsp_response":
                logger.debug("bad ocsp data")
                return False, None
            elif crl1.native["other_rev_info"]["response_status"] != "successful":
                logger.debug(f"ocsp response status failure: {crl1.native['other_rev_info']['response_status']}")
                return False, None
            elif crl1.native["other_rev_info"]["response_bytes"]["response_type"] == "basic_ocsp_response":
                crlresp : ocsp.BasicOCSPResponse = crl1.chosen[1][1][1].parsed
                #crlresp = crl1.native["other_rev_info"]["response_bytes"]["response"]
                produced_at = crlresp["tbs_response_data"]["produced_at"].native
                cert_was_checked = False
                next_check_at = None
                for ccert in crlresp["tbs_response_data"]["responses"]:
                    cert_id = ccert["cert_id"]
                    if (
                        cert_id["serial_number"].native == cert.serial_number
                        and self._verify_ocsp_cert_id(cert_id, issuer_cert)
                    ):
                        cert_was_checked = True
                        next_check_at = ccert["next_update"].native
                        break
                sigalgo = crlresp["signature_algorithm"]["algorithm"].native
                sig = crlresp["signature"].native
                sigok = False
                ocspcert = None
                for othercert in crlresp["certs"]:
                    for ext in othercert["tbs_certificate"]["extensions"]:
                        if ext["extn_id"].native == "extended_key_usage" and "ocsp_signing" in ext["extn_value"].native:
                            ocspcert = cx509.load_der_x509_certificate(othercert.dump())
                if ocspcert:
                    if self.validate_certificate(ocspcert, othercerts) and not sigok:
                        try:
                            public_key = ocspcert.public_key()
                            signedData = crlresp["tbs_response_data"].dump()
                            hash_cls = self._resolve_hash_cls(sigalgo)
                            if hash_cls is None:
                                raise ValueError(f"Unsupported OCSP signature algorithm: {sigalgo}")

                            public_key.verify(
                                sig,
                                signedData,
                                padding.PKCS1v15(),
                                hash_cls(),
                            )
                            sigok = True
                        except Exception:
                            logger.debug(f"ocsp signing certificate is invalid")
                            pass
                now = datetime.datetime.now(datetime.UTC)
                if produced_at > now:
                    logger.debug("ocsp produced_at is in the future")
                    return False, None
                if next_check_at is not None and next_check_at < now:
                    logger.debug("ocsp response is stale")
                    return False, None
                if sigok and cert_was_checked:
                    return True, (produced_at, next_check_at)
                logger.debug(f"ocsp cannot be verified")
            else:
                logger.debug(f"ocsp unknown response type: {crl1.native['other_rev_info']['response_bytes']['response_type']}")
        return False, None

    def verify_tsp_data(self, signed_data, tspdata, othercerts):
        if tspdata['encap_content_info']['content_type'].native == 'tst_info':
            (_, _, tcrldata, tcert, tothercerts, _, tsignatureok) = self.decompose_signed_data(b'', tspdata)
            if not tsignatureok:
                return False, None

            def getleaf(xcert):
                leaf_certificate = None
                for cert in tothercerts:
                    if xcert.issuer == cert.subject:
                        return cert

            def seekForRoot(xcert, certs):
                xcertsigner = xcert.extensions.get_extension_for_class(
                    cx509.AuthorityKeyIdentifier
                ).value.key_identifier
                for cert in certs:
                    certsubject = cert.extensions.get_extension_for_class(
                        cx509.SubjectKeyIdentifier
                    ).value.key_identifier
                    if xcertsigner == certsubject:
                        return True
                for cert in self.certs:
                    try:
                        certsubject = cert.extensions.get_extension_for_class(
                            cx509.SubjectKeyIdentifier
                        ).value.key_identifier
                        if xcertsigner == certsubject:
                            return True
                    except extensions.ExtensionNotFound:
                        pass
                return False

            # tcert must have timeStamping EKU
            eku_extension = tcert.extensions.get_extension_for_class(
                cx509.ExtendedKeyUsage
            )
            if not eku_extension.critical:
                logger.debug("The EKU extension is not critical.")
                return False, None

            if cx509.ExtendedKeyUsageOID.TIME_STAMPING not in eku_extension.value:
                logger.debug("The EKU extension does not have KeyPurposeID id-kp-timeStamping.")
                return False, None

            leaf_certificate = getleaf(tcert)
            if leaf_certificate:
                bc_extension = leaf_certificate.extensions.get_extension_for_class(
                    cx509.BasicConstraints
                )
                eku_extension = leaf_certificate.extensions.get_extension_for_class(
                    cx509.ExtendedKeyUsage
                )
                if not bc_extension.critical or not bc_extension.value.ca:
                    logger.debug("Leaf certificate is not CA.")
                    return False, None
                #elif not eku_extension.critical:
                #    # leaf cert must have timeStamping EKU
                #    msg = "The EKU extension is not critical."
                #    raise VerificationError(msg)
                elif cx509.ExtendedKeyUsageOID.TIME_STAMPING not in eku_extension.value:
                    logger.debug("The EKU extension does not have KeyPurposeID id-kp-timeStamping.")
                    return False, None

                while True:
                    cert = getleaf(leaf_certificate)
                    if cert:
                        leaf_certificate = cert
                    else:
                        break

                # leaf_certificate must be signed by known CA
                # ok = self.verifier.verify(leaf_certificate, othercerts)
                ok = seekForRoot(leaf_certificate, othercerts)
            else:
                # tcert may not have subjectAltName
                #ok = self.verifier.verify(tcert, othercerts)
                ok = seekForRoot(tcert, othercerts)

            if not ok:
                logger.debug("No leaf certificate found in the chain.")
                return False, None

            tst = tspdata['encap_content_info']['content'].parsed
            signature_bytes = signed_data['signer_infos'][0]['signature'].native
            md = hashlib.sha256(signature_bytes).digest()
            if md == tst['message_imprint']['hashed_message'].native:
                return True, tst['gen_time'].native

        return False, None

    def verify(self, datas:bytes, datau:bytes) -> list[tuple[bool, bool, bool]]:
        (signed_data, tspdata, crldata, cert, othercerts, hashok, signatureok) = self.decompose_signed_data(datas, datau)
        certok = self.validate_certificate(cert, othercerts)
        if certok and crldata.native is not None:
            ok, info = self.verify_ocsp_data(cert, othercerts, crldata)
            # info = (produced_at, next_check_at)
            if not ok:
                certok = False
        if certok and tspdata is not None:
            ok, info = self.verify_tsp_data(signed_data, tspdata, othercerts)
            #print('info:', info)
            # info = gen_time
            if not ok:
                raise ValueError("Invalid TSP")

        return hashok, signatureok, certok



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
    cls = SignatureVerifier(certs)
    return cls.verify(datas, datau)
