# *-* coding: utf-8 *-*
import datetime
import hashlib
import logging

import certifi
import certvalidator
from asn1crypto import cms, core, ocsp, pem, x509
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

logger = logging.getLogger(__name__)


class Result(object):
    """
    Result of signature verification
    Members:
        signed_data: cms.SignedData
            The signed data structure.
        crldata: cms.RevocationInfoChoices
            The certificate revocation list data structure.
        cert: x509.Certificate
            The signer's certificate.
        othercerts: list[x509.Certificate]
            List of other certificates included in the signed data.
        tsp_data: cms.SignedData | None
            The time-stamp protocol data structure, or None if not present.
        hashok: bool
            True if hash is matches, False otherwise.
        signatureok: bool
            True if signature is valid, False otherwise.
        certok: bool
            True if certificate is valid, False otherwise.
        ocspok: bool|None
            True if OCSP is valid, False if invalid, None if not present.
        ocspdata: tuple[datetime.datetime, datetime.datetime | None] | None
            Tuple of OCSP produced_at and next_check_at datetimes,
            or None if not present.
        ocspmsg: str|None
            OCSP verification message, or None if not present.
        tspok: bool|None
            True if TSP is valid, False if invalid, None if not present.
        tspdata: datetime.datetime|None
            TSP produced_at datetime, or None if not present.
        tspmsg: str|None
            TSP verification message, or None if not present.
    """

    def __init__(
        self,
        signed_data: cms.SignedData,
        crldata: cms.RevocationInfoChoices,
        cert: x509.Certificate,
        othercerts: list[x509.Certificate],
        hashok: bool,
        signatureok: bool,
        tsp_data: cms.SignedData | None = None,
    ):
        self.signed_data = signed_data
        self.crldata = crldata
        self.cert = cert
        self.othercerts = othercerts
        self.hashok = hashok
        self.signatureok = signatureok
        self.tsp_data = tsp_data
        #
        self.certok: bool | None = None
        self.ocspok: bool | None = None
        self.ocspdata: tuple[datetime.datetime, datetime.datetime | None] | None = None
        self.ocspmsg: str | None = None
        self.tspok: bool | None = None
        self.tspdata: datetime.datetime | None = None
        self.tspmsg: str | None = None

    def ocsp_result(
        self,
        ocspok: bool | None,
        ocspdata: tuple[datetime.datetime, datetime.datetime | None] | None,
        ocspmsg: str | None = None,
    ):
        self.ocspok = ocspok
        self.ocspdata = ocspdata
        self.ocspmsg = ocspmsg

    def tsp_result(
        self,
        tspok: bool | None,
        tspdata: datetime.datetime | None,
        tspmsg: str | None = None,
    ):
        self.tspok = tspok
        self.tspdata = tspdata
        self.tspmsg = tspmsg


class SignatureVerifier(object):
    def __init__(self, trusted_certs: list[bytes | x509.Certificate] | None = None):
        certs = []
        with open(certifi.where(), "rb") as f:
            pem_data = f.read()
            for entry in pem.unarmor(pem_data, multiple=True):
                certs.append(x509.Certificate.load(entry[2]))
        if trusted_certs is not None:
            for cert_bytes in trusted_certs:
                if pem.detect(cert_bytes):
                    cert_bytes = pem.unarmor(cert_bytes)[2]
                certs.append(x509.Certificate.load(cert_bytes))
        self.trusted_certs = certs

    def _validator(
        self,
        cert: x509.Certificate,
        othercerts: list[x509.Certificate] | None = None,
        trustedcerts: list[x509.Certificate] | None = None,
        allow_fetching: bool = False,
    ) -> certvalidator.CertificateValidator:
        validation_context = certvalidator.ValidationContext(
            trust_roots=trustedcerts,
            allow_fetching=allow_fetching,
            revocation_mode="soft-fail",
            moment=datetime.datetime.now(tz=datetime.timezone.utc),
        )
        validator = certvalidator.CertificateValidator(
            cert,
            intermediate_certs=othercerts,
            validation_context=validation_context,
        )
        return validator

    def validate_certificate(
        self,
        cert: x509.Certificate,
        othercerts: list[x509.Certificate] | None = None,
        key_usage: list[str] | None = None,
        extended_key_usage: list[str] | None = None,
        allow_fetching=False,
    ):
        prog = self._validator(cert, othercerts, self.trusted_certs, allow_fetching)
        try:
            prog.validate_usage(
                key_usage=set(key_usage or []),
                extended_key_usage=set(extended_key_usage or []),
            )
            return True
        except certvalidator.errors.PathBuildingError as exc:
            logger.debug("Path building error: %s", exc)
        except certvalidator.errors.PathValidationError as exc:
            logger.debug("Path validation error: %s", exc)
        except certvalidator.errors.ValidationError as exc:
            logger.debug("Validation error: %s", exc)
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

    def decompose_signed_data(
        self, signaturebytes: cms.SignedData | bytes, datau: bytes
    ) -> Result:
        if isinstance(signaturebytes, bytes):
            signed_data = cms.ContentInfo.load(signaturebytes)["content"]
        else:
            signed_data = signaturebytes
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
        othercerts: list[cms.Certificate] = []
        serial = signed_data["signer_infos"][0]["sid"].native["serial_number"]
        for pdfcert in signed_data["certificates"]:
            if serial != pdfcert.native["tbs_certificate"]["serial_number"]:
                othercerts.append(pdfcert.chosen)
            else:
                if cert is not None:
                    raise ValueError(
                        "Multiple signer certificates with the same serial"
                    )
                cert = pdfcert.chosen
        if cert is None:
            raise ValueError("Signer certificate not found in signed data")

        public_key = cx509.load_pem_x509_certificate(
            pem.armor("CERTIFICATE", cert.dump())
        ).public_key()

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

        tspdata: cms.SignedData | None = None
        for attr in signed_data["signer_infos"][0]["unsigned_attrs"]:
            if attr["type"].native == "signature_time_stamp_token":
                for v in attr["values"]:
                    if v["content_type"].native == "signed_data":
                        tspdata = v["content"]
        crls = signed_data["crls"]

        return Result(signed_data, crls, cert, othercerts, hashok, signatureok, tspdata)

    def _verify_ocsp_cert_id(self, cert_id, issuer_cert):
        hash_name = cert_id["hash_algorithm"]["algorithm"].native
        hash_cls = self._resolve_hash_cls(hash_name)

        issuer_asn1 = x509.Certificate.load(
            issuer_cert.public_bytes(serialization.Encoding.DER)
        )
        issuer_name = issuer_asn1["tbs_certificate"]["subject"].dump()
        issuer_key_bitstring = issuer_asn1["tbs_certificate"][
            "subject_public_key_info"
        ]["public_key"]
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

    def verify_ocsp_data(self, result: Result) -> None:
        if result.crldata.native is not None:
            result.ocsp_result(None, None, "no OCSP data found")
            return
        cert = result.cert
        othercerts = result.othercerts
        crldata = result.crldata
        issuer_cert = None
        for item in othercerts:
            if item.subject == cert.issuer:
                issuer_cert = item
                break
        if issuer_cert is None:
            result.ocsp_result(False, None, "cannot resolve issuer certificate")
            return

        if len(crldata) != 1:
            result.ocsp_result(False, None, "unsupported number of OCSP responses")
            return
        crl1 = crldata[0]
        if crl1.native["other_rev_info_format"] != "ocsp_response":
            result.ocsp_result(False, None, "bad ocsp data")
            return
        elif crl1.native["other_rev_info"]["response_status"] != "successful":
            result.ocsp_result(False, None, "ocsp response status failure")
            return
        elif (
            crl1.native["other_rev_info"]["response_bytes"]["response_type"]
            == "basic_ocsp_response"
        ):
            crlresp: ocsp.BasicOCSPResponse = crl1.chosen[1][1][1].parsed
            # crlresp = crl1.native["other_rev_info"]["response_bytes"]["response"]
            produced_at = crlresp["tbs_response_data"]["produced_at"].native
            cert_was_checked = False
            next_check_at = None
            for ccert in crlresp["tbs_response_data"]["responses"]:
                cert_id = ccert["cert_id"]
                if cert_id[
                    "serial_number"
                ].native == cert.serial_number and self._verify_ocsp_cert_id(
                    cert_id, issuer_cert
                ):
                    cert_was_checked = True
                    next_check_at = ccert["next_update"].native
                    break
            ocspcert = None
            for othercert in crlresp["certs"]:
                for ext in othercert["tbs_certificate"]["extensions"]:
                    if (
                        ext["extn_id"].native == "extended_key_usage"
                        and "ocsp_signing" in ext["extn_value"].native
                    ):
                        ocspcert = othercert.chosen
            if ocspcert is None:
                result.ocsp_result(False, None, "signing certificate not found")
                return
            if not self.validate_certificate(ocspcert, othercerts):
                result.ocsp_result(False, None, "signing certificate validation failed")
                return
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
                result.ocsp_result(False, None, "signing certificate is invalid")
                return
            now = datetime.datetime.now(datetime.UTC)
            if produced_at > now:
                result.ocsp_result(False, None, "value of produced_at is in the future")
                return
            if next_check_at is not None and next_check_at < now:
                result.ocsp_result(False, None, "response is stale")
                return
            if cert_was_checked:
                result.ocsp_result(True, (produced_at, next_check_at), "valid")
                return
            result.ocsp_result(False, None, "response not for signing certificate")
        else:
            result.ocsp_result(False, None, "unknown response type")

    def verify_tsp_data(self, result: Result):
        if result.tsp_data is None:
            result.tsp_result(None, None, "no TSP data found")
            return
        if result.tsp_data["encap_content_info"]["content_type"].native != "tst_info":
            raise ValueError(
                f"Unsupported TSP content type: {result.tsp_data['encap_content_info']['content_type'].native}"
            )

        sub = self.decompose_signed_data(result.tsp_data, b"")
        if not sub.signatureok:
            result.tsp_result(False, None, "TSP signature is invalid")
            return

        prog = self._validator(
            sub.cert, othercerts=sub.othercerts, trustedcerts=self.trusted_certs
        )
        try:
            prog.validate_usage(key_usage=set(), extended_key_usage={"time_stamping"})
        except certvalidator.errors.PathBuildingError as exc:
            raise ValueError(f"Invalid TSP certificate path: {exc}") from exc
        except certvalidator.errors.PathValidationError as exc:
            raise ValueError(f"TSP certificate path validation error: {exc}") from exc
        except certvalidator.errors.ValidationError as exc:
            raise ValueError(f"TSP certificate validation error: {exc}") from exc

        tst = result.tsp_data["encap_content_info"]["content"].parsed
        if 0:
            # TODO: verify the message imprint against the signed data hash
            signature_bytes = tspdata["signer_infos"][0]["signature"].native
            md = hashlib.sha256(signature_bytes).digest()
            if md == tst["message_imprint"]["hashed_message"].native:
                result.tsp(True, tst["gen_time"].native)
        result.tsp_result(True, tst["gen_time"].native, "valid")

    def verify_data(self, datas: bytes, datau: bytes) -> Result:
        """
        Verify signed data.

        :return:
            Result
        """
        result = self.decompose_signed_data(datas, datau)
        result.certok = self.validate_certificate(result.cert, result.othercerts)
        self.verify_ocsp_data(result)
        self.verify_tsp_data(result)

        return result


def verify(
    datas: bytes,
    datau: bytes,
    trusted_certs: list[bytes | x509.Certificate] | None = None,
) -> Result:
    """
    Verify signed data.

    :return:
        Result
    """
    cls = SignatureVerifier(trusted_certs)
    return cls.verify_data(datas, datau)
