# *-* coding: utf-8 *-*
import hashlib
import datetime
import logging

import certifi
from asn1crypto import x509, core, pem, cms, ocsp
import certvalidator

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger(__name__)


class SignatureVerifier(object):
    def __init__(self, trusted_certs:list[bytes]|None=None):
        certs = []
        with open(certifi.where(), "rb") as f:
            pem_data = f.read()
            for entry in pem.unarmor(pem_data, multiple=True):
                certs.append(x509.Certificate.load(entry[2]))
        if trusted_certs is not None:
            for cert_bytes in trusted_certs:
                if pem.detect(cert_bytes):
                    entry = pem.unarmor(cert_bytes)
                certs.append(x509.Certificate.load(entry[2]))
        self.trusted_certs = certs

    def _validator(
        self,
        cert:x509.Certificate,
        othercerts:list[x509.Certificate]|None=None,
        trustedcerts:list[x509.Certificate]|None=None,
        allow_fetching:bool=False,
    ) -> certvalidator.CertificateValidator:
        validation_context = certvalidator.ValidationContext(
            trust_roots=trustedcerts,
            allow_fetching=allow_fetching,
            revocation_mode="soft-fail",
            moment=datetime.datetime.now(tz=datetime.timezone.utc)
        )
        validator = certvalidator.CertificateValidator(
            cert,
            intermediate_certs=othercerts,
            validation_context=validation_context,
        )
        return validator

    def validate_certificate(self,
        cert:x509.Certificate,
        othercerts:list[x509.Certificate]|None=None,
        key_usage:list[str]|None=None,
        extended_key_usage:list[str]|None=None,
        allow_fetching=False,
    ):
        prog = self._validator(cert, othercerts, self.trusted_certs, allow_fetching)
        try:
            path = prog.validate_usage(
                key_usage=set(key_usage or []),
                extended_key_usage=set(extended_key_usage or [])
            )
        except certvalidator.errors.PathBuildingError as exc:
            logger.debug("Path building error: %s", exc)
        except certvalidator.errors.PathValidationError as exc:
            logger.debug("Path validation error: %s", exc)
        except certvalidator.errors.ValidationError as exc:
            logger.debug("Validation error: %s", exc)
        else:
            logger.debug("Validation path:")
            for entry in path:
                logger.debug("%s %s", entry.serial_number, entry.subject.native)
            return True
        return False

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

    def decompose_signed_data(self, signaturebytes: bytes, datau: bytes) -> tuple:
        # return (signed_data, tspdata, crls, cert, othercerts, hashok, signatureok)
        signed_data = cms.ContentInfo.load(signaturebytes)["content"]
        return self._decompose_signed_data(signed_data, datau)

    def _decompose_signed_data(self, signed_data: cms.ContentInfo, datau: bytes) -> tuple:
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
                if cert is not None:
                    raise ValueError("Multiple signer certificates with the same serial")
                cert = pdfcert.chosen
        if cert is None:
            raise ValueError("Signer certificate not found in signed data")

        public_key = cx509.load_pem_x509_certificate(pem.armor("CERTIFICATE", cert.dump())).public_key()

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
                    padding=padding.PSS(mgf, salt_length),
                    algorithm=getattr(hashes, salgo)(),
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
                    padding=padding.PKCS1v15(),
                    algorithm=getattr(hashes, algo.upper())(),
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

    def verify_ocsp_data(self, cert, othercerts, crldata) -> tuple[bool|None, list[datetime.datetime]|None]:
        issuer_cert = None
        for item in othercerts:
            if item.subject == cert.issuer:
                issuer_cert = item
                break
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
                ocspcert = None
                for othercert in crlresp["certs"]:
                    for ext in othercert["tbs_certificate"]["extensions"]:
                        if ext["extn_id"].native == "extended_key_usage" and "ocsp_signing" in ext["extn_value"].native:
                            ocspcert = othercert.chosen
                if ocspcert is None:
                    return False, None
                if not self.validate_certificate(ocspcert, othercerts):
                    return False, None
                sigalgo = crlresp["signature_algorithm"]["algorithm"].native
                sig = crlresp["signature"].native
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
                except Exception:
                    logger.debug(f"ocsp signing certificate is invalid")
                    return False, None
                now = datetime.datetime.now(datetime.UTC)
                if produced_at > now:
                    logger.debug("ocsp produced_at is in the future")
                    return False, None
                if next_check_at is not None and next_check_at < now:
                    logger.debug("ocsp response is stale")
                    return False, None
                if cert_was_checked:
                    return True, (produced_at, next_check_at)
                logger.debug("ocsp cannot be verified")
            else:
                logger.debug(f"ocsp unknown response type: {crl1.native['other_rev_info']['response_bytes']['response_type']}")
        return False, None

    def verify_tsp_data(self, signed_data: bytes, tspdata):
        #tsp = cms.ContentInfo.load(tspdata)["content"]

        if tspdata['encap_content_info']['content_type'].native != 'tst_info':
            raise ValueError(f"Unsupported TSP content type: {tspdata['encap_content_info']['content_type'].native}")

        (_, _, tsp_crl_data, tsp_cert, tsp_othercerts, _, signatureok) = self._decompose_signed_data(tspdata, b'')
        if not signatureok:
            return False, None

        prog = self._validator(tsp_cert, othercerts=tsp_othercerts, trustedcerts=self.trusted_certs)
        try:
            prog.validate_usage(
                key_usage=set([]),
                extended_key_usage=set(["time_stamping"])
            )
        except certvalidator.errors.PathBuildingError as exc:
            raise ValueError(f"Invalid TSP certificate path: {exc}") from exc
        except certvalidator.errors.PathValidationError as exc:
            raise ValueError(f"TSP certificate path validation error: {exc}") from exc
        except certvalidator.errors.ValidationError as exc:
            raise ValueError(f"TSP certificate validation error: {exc}") from exc

        tst = tspdata['encap_content_info']['content'].parsed
        if 0:
            # TODO: verify the message imprint against the signed data hash
            signature_bytes = tspdata['signer_infos'][0]['signature'].native
            md = hashlib.sha256(signature_bytes).digest()
            if md == tst['message_imprint']['hashed_message'].native:
                return True, tst['gen_time'].native
        return True, tst['gen_time'].native

        #return False, tst['gen_time'].native

    def verify_data(
            self,
            datas:bytes,
            datau:bytes
        ) -> tuple[bool, bool, bool, bool|None, list[datetime.datetime]|None, bool|None, datetime.datetime|None]:
        """
        Verify signed data.
        :return:
            hashok, signatureok, certok, ocspok, ocspdata, tspok, tspdata

            hashok: bool
                True if hash is matches, False otherwise.
            signatureok: bool
                True if signature is valid, False otherwise.
            certok: bool
                True if certificate is valid, False otherwise.
            ocspok: bool|None
                True if OCSP is valid, False if invalid, None if not present.
            ocspdata: list[datetime.datetime]|None
                List of OCSP produced_at and next_check_at datetimes,
                or None if not present.
            tspok: bool|None
                True if TSP is valid, False if invalid, None if not present.
            tspdata: datetime.datetime|None
                TSP produced_at datetime, or None if not present.
        """
        (signed_data, tsp_data, crldata, cert, othercerts, hashok, signatureok) = self.decompose_signed_data(datas, datau)
        certok = self.validate_certificate(cert, othercerts)
        ocspok, ocspdata = None, None
        if crldata.native is not None:
            ocspok, ocspdata = self.verify_ocsp_data(cert, othercerts, crldata)
            # ocspdata = (produced_at, next_check_at)
        tspok, tspdata = None, None
        if tsp_data is not None:
            tspok, tspdata = self.verify_tsp_data(signed_data, tsp_data)

        return (hashok, signatureok, certok, ocspok, ocspdata, tspok, tspdata)


def verify(
        datas:bytes,
        datau:bytes,
        trusted_certs:list[bytes]|None=None
    ) -> tuple[bool, bool, bool, bool|None, list[datetime.datetime]|None, bool|None, datetime.datetime|None]:
    """
    Verify signed data.
    :return:
        hashok, signatureok, certok, ocspok, ocspdata, tspok, tspdata

        hashok: bool
            True if hash is matches, False otherwise.
        signatureok: bool
            True if signature is valid, False otherwise.
        certok: bool
            True if certificate is valid, False otherwise.
        ocspok: bool|None
            True if OCSP is valid, False if invalid, None if not present.
        ocspdata: list[datetime.datetime]|None
            List of OCSP produced_at and next_check_at datetimes,
            or None if not present.
        tspok: bool|None
            True if TSP is valid, False if invalid, None if not present.
        tspdata: datetime.datetime|None
            TSP produced_at datetime, or None if not present.
    """
    cls = SignatureVerifier(trusted_certs)
    return cls.verify_data(datas, datau)
