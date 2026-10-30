from __future__ import annotations

import datetime
import logging
import warnings

import certifi
from asn1crypto import algos, cms, core, ocsp, pem, tsp, x509
from cryptography import x509 as cx509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import verification

from endesive.exceptions import (
    HashAlgorithmError,
    SignatureVerificationError,
    TSPVerificationError,
)

logger = logging.getLogger(__name__)

# asn1crypto style key usage names which differ from cryptography's KeyUsage
_KEY_USAGE_ALIASES = {"non_repudiation": "content_commitment"}
# asn1crypto style extended key usage names -> dotted OIDs
_EKU_NAME_TO_OID = {name: oid for oid, name in x509.KeyPurposeId._map.items()}


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
        certtime: datetime.datetime|None
            The moment the signer's certificate path was validated for: the
            time of a valid TSP token, otherwise the time of verification.
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
        self.certtime: datetime.datetime | None = None
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
    """CMS/S-MIME Signature verifier.

    Verifies digital signatures in CMS/S-MIME format with certificate validation
    and optional OCSP/TSP verification.
    """

    def __init__(
        self, trusted_certs: list[bytes | x509.Certificate] | None = None
    ) -> None:
        """Initialize signature verifier.

        Args:
            trusted_certs: Optional list of trusted root certificates (bytes in PEM/DER or x509.Certificate objects)
        """
        certs: list[cx509.Certificate] = []
        with open(certifi.where(), "rb") as f:
            pem_data = f.read()
        with warnings.catch_warnings():
            # some bundled roots trigger RFC 5280 deprecation warnings
            warnings.simplefilter("ignore")
            for entry in pem.unarmor(pem_data, multiple=True):
                try:
                    certs.append(cx509.load_der_x509_certificate(entry[2]))
                except ValueError as exc:
                    logger.debug("Skipping unparsable trusted certificate: %s", exc)
        if trusted_certs is not None:
            for cert in trusted_certs:
                certs.append(self._to_cryptography(cert))
        self.trusted_certs = certs

    @staticmethod
    def _to_cryptography(
        cert: bytes | x509.Certificate | cx509.Certificate,
    ) -> cx509.Certificate:
        if isinstance(cert, cx509.Certificate):
            return cert
        if isinstance(cert, x509.Certificate):
            return cx509.load_der_x509_certificate(cert.dump())
        if pem.detect(cert):
            cert = pem.unarmor(cert)[2]
        return cx509.load_der_x509_certificate(cert)

    @staticmethod
    def _ca_key_usage(policy, cert, ext: cx509.KeyUsage | None) -> None:
        if ext is not None and not ext.key_cert_sign:
            raise ValueError("CA certificate key usage does not permit keyCertSign")

    def _validator(
        self,
        trustedcerts: list[cx509.Certificate] | None = None,
        validation_time: datetime.datetime | None = None,
    ) -> verification.ClientVerifier:
        # RFC 5280 style CA checks; end-entity usage is checked separately
        # because signing certificates rarely carry WebPKI client EKUs
        ca_policy = (
            verification.ExtensionPolicy.permit_all()
            # cA flag and pathLenConstraint are enforced by the chain builder
            .require_present(
                cx509.BasicConstraints,
                verification.Criticality.AGNOSTIC,
                None,
            )
            .may_be_present(
                cx509.KeyUsage,
                verification.Criticality.AGNOSTIC,
                self._ca_key_usage,
            )
        )
        builder = (
            verification.PolicyBuilder()
            .store(verification.Store(trustedcerts or []))
            .time(validation_time or datetime.datetime.now(tz=datetime.timezone.utc))
            .extension_policies(
                ca_policy=ca_policy,
                ee_policy=verification.ExtensionPolicy.permit_all(),
            )
        )
        return builder.build_client_verifier()

    @staticmethod
    def _check_usage(
        cert: cx509.Certificate,
        key_usage: list[str] | set[str] | None,
        extended_key_usage: list[str] | set[str] | None,
    ) -> None:
        if key_usage:
            try:
                ku = cert.extensions.get_extension_for_class(cx509.KeyUsage).value
            except cx509.ExtensionNotFound as exc:
                raise ValueError("certificate has no key usage extension") from exc
            for name in key_usage:
                attr = _KEY_USAGE_ALIASES.get(name, name)
                try:
                    allowed = getattr(ku, attr)
                except (AttributeError, ValueError):
                    allowed = False
                if not allowed:
                    raise ValueError(f"certificate key usage does not permit {name}")
        if extended_key_usage:
            try:
                eku = cert.extensions.get_extension_for_class(
                    cx509.ExtendedKeyUsage
                ).value
            except cx509.ExtensionNotFound as exc:
                raise ValueError(
                    "certificate has no extended key usage extension"
                ) from exc
            for name in extended_key_usage:
                dotted = _EKU_NAME_TO_OID.get(name, name)
                if cx509.ObjectIdentifier(dotted) not in eku:
                    raise ValueError(
                        f"certificate extended key usage does not permit {name}"
                    )

    def _verify_certificate(
        self,
        cert: x509.Certificate | cx509.Certificate,
        othercerts: list[x509.Certificate] | None = None,
        key_usage: list[str] | set[str] | None = None,
        extended_key_usage: list[str] | set[str] | None = None,
        validation_time: datetime.datetime | None = None,
    ) -> list[cx509.Certificate]:
        """Build and validate the certificate path, raising on failure."""
        leaf = self._to_cryptography(cert)
        intermediates = [self._to_cryptography(c) for c in othercerts or []]
        validator = self._validator(self.trusted_certs, validation_time)
        chain = validator.verify(leaf, intermediates).chain
        self._check_usage(leaf, key_usage, extended_key_usage)
        return chain

    def validate_certificate(
        self,
        cert: x509.Certificate | cx509.Certificate,
        othercerts: list[x509.Certificate] | None = None,
        key_usage: list[str] | None = None,
        extended_key_usage: list[str] | None = None,
        allow_fetching=False,
        validation_time: datetime.datetime | None = None,
    ):
        """Validate certificate path against trusted roots.

        Revocation is not checked here (``allow_fetching`` is accepted for
        backward compatibility and ignored); see :meth:`verify_ocsp_data`.

        Args:
            validation_time: Moment the path must be valid at; default now.
        """
        try:
            self._verify_certificate(
                cert, othercerts, key_usage, extended_key_usage, validation_time
            )
            return True
        except verification.VerificationError as exc:
            logger.debug("Path validation error: %s", exc)
        except ValueError as exc:
            logger.debug("Validation error: %s", exc)
        return False

    def _resolve_hash_cls(self, algo_name):
        if algo_name is None:
            hashcls = None
        else:
            normalized = algo_name.upper().replace("-", "")
            if normalized.endswith("RSA"):
                normalized = normalized[:-3].rstrip("_")
            try:
                hashcls = getattr(hashes, normalized)
            except AttributeError as exc:
                raise HashAlgorithmError(
                    f"Invalid hash algorithm: {algo_name}"
                ) from exc
        if hashcls is None:
            raise HashAlgorithmError(f"Invalid hash algorithm: {algo_name}")
        return hashcls

    @staticmethod
    def _find_signer_certificate(
        signer_info: cms.SignerInfo, certificates: cms.CertificateSet
    ) -> tuple[x509.Certificate, list[x509.Certificate]]:
        """Split embedded certificates into the signer and the remaining ones."""
        sid = signer_info["sid"]
        cert = None
        othercerts: list[x509.Certificate] = []
        for choice in certificates or []:
            if choice.name != "certificate":
                # attribute and other certificate formats are not used here
                continue
            candidate = choice.chosen
            if sid.name == "issuer_and_serial_number":
                matches = (
                    candidate.serial_number == sid.chosen["serial_number"].native
                    and candidate.issuer == sid.chosen["issuer"]
                )
            else:
                matches = candidate.key_identifier == sid.chosen.native
            if not matches:
                othercerts.append(candidate)
                continue
            if cert is not None:
                raise SignatureVerificationError(
                    "Multiple signer certificates match the signer identifier"
                )
            cert = candidate
        if cert is None:
            raise SignatureVerificationError(
                "Signer certificate not found in signed data"
            )
        return cert, othercerts

    @staticmethod
    def _signed_attribute(attrs: cms.CMSAttributes, name: str):
        """Return the single value of a signed attribute, or None if absent."""
        values = [attr["values"] for attr in attrs if attr["type"].native == name]
        if not values:
            return None
        if len(values) != 1 or len(values[0]) != 1:
            raise SignatureVerificationError(
                f"Signed attribute {name} must occur exactly once with one value"
            )
        return values[0][0].native

    def decompose_signed_data(
        self, signaturebytes: cms.SignedData | bytes, datau: bytes
    ) -> Result:
        """Parse CMS SignedData and check message digest and signature.

        Args:
            signaturebytes: DER encoded ContentInfo or parsed SignedData.
            datau: Detached content; when empty the encapsulated content is used.
        """
        if isinstance(signaturebytes, bytes):
            content_info = cms.ContentInfo.load(signaturebytes)
            if content_info["content_type"].native != "signed_data":
                raise SignatureVerificationError(
                    f"Unsupported content type: {content_info['content_type'].native}"
                )
            signed_data = content_info["content"]
        else:
            signed_data = signaturebytes
        if len(signed_data["signer_infos"]) != 1:
            raise SignatureVerificationError(
                "Expected to find exactly one SignerInfo structure"
            )
        signer_info = signed_data["signer_infos"][0]
        encap = signed_data["encap_content_info"]

        content = datau
        if not content:
            econtent = encap["content"]
            if isinstance(econtent, core.OctetString):
                # id-data content
                content = econtent.native
            elif isinstance(econtent, core.ParsableOctetString):
                # typed content, e.g. TSTInfo
                content = econtent.contents
        content = content or b""

        digest_name = signer_info["digest_algorithm"]["algorithm"].native
        digest = hashes.Hash(self._resolve_hash_cls(digest_name)())
        digest.update(content)
        md_data = digest.finalize()

        attrs = signer_info["signed_attrs"]
        if attrs is not None and not isinstance(attrs, core.Void):
            md_signed = self._signed_attribute(attrs, "message_digest")
            content_type = self._signed_attribute(attrs, "content_type")
            hashok = md_signed == md_data and (
                content_type is None or content_type == encap["content_type"].native
            )
            # signature covers the DER SET OF, not the [0] IMPLICIT tagged form
            signed_bytes = b"\x31" + attrs.dump()[1:]
        else:
            hashok = True
            signed_bytes = content

        cert, othercerts = self._find_signer_certificate(
            signer_info, signed_data["certificates"]
        )

        try:
            self._verify_signature(
                self._to_cryptography(cert).public_key(),
                signer_info["signature"].native,
                signed_bytes,
                signer_info["signature_algorithm"],
                default_hash=digest_name,
            )
            signatureok = True
        except (SignatureVerificationError, HashAlgorithmError):
            # unsupported algorithm, not a bad signature
            raise
        except (InvalidSignature, TypeError, ValueError) as exc:
            logger.debug("Signature verification failed: %s", exc)
            signatureok = False

        tspdata: cms.SignedData | None = None
        for attr in signer_info["unsigned_attrs"] or []:
            if attr["type"].native == "signature_time_stamp_token":
                for v in attr["values"]:
                    if v["content_type"].native == "signed_data":
                        tspdata = v["content"]
        crls = signed_data["crls"]

        return Result(signed_data, crls, cert, othercerts, hashok, signatureok, tspdata)

    @staticmethod
    def _to_asn1(cert: x509.Certificate | cx509.Certificate) -> x509.Certificate:
        if isinstance(cert, x509.Certificate):
            return cert
        return x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))

    def _verify_ocsp_cert_id(self, cert_id, issuer_cert):
        hash_name = cert_id["hash_algorithm"]["algorithm"].native
        hash_cls = self._resolve_hash_cls(hash_name)

        issuer_asn1 = self._to_asn1(issuer_cert)
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

    def _find_issuer(
        self, cert: x509.Certificate, othercerts: list[x509.Certificate]
    ) -> x509.Certificate | cx509.Certificate | None:
        for item in othercerts:
            if item.subject == cert.issuer:
                return item
        # signer certificate may be issued directly by a trusted root
        for trusted in self.trusted_certs:
            if x509.Name.load(trusted.subject.public_bytes()) == cert.issuer:
                return trusted
        return None

    def _verify_signature(
        self,
        public_key,
        signature: bytes,
        data: bytes,
        sigalgo: algos.SignedDigestAlgorithm,
        default_hash: str | None = None,
    ) -> None:
        """Verify a raw signature, raising on failure.

        Args:
            default_hash: Hash used when the signature algorithm does not imply
                one (e.g. plain rsaEncryption in CMS SignerInfo).
        """
        if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
            return
        try:
            hash_name = sigalgo.hash_algo
        except ValueError:
            hash_name = default_hash
        hash_cls = self._resolve_hash_cls(hash_name)
        # dispatch on the key type: older endesive versions labelled ECDSA
        # signatures as rsassa_pkcs1v15
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hash_cls()))
        elif not isinstance(public_key, rsa.RSAPublicKey):
            raise SignatureVerificationError(
                f"Unsupported public key type: {type(public_key).__name__}"
            )
        elif sigalgo.signature_algo == "rsassa_pss":
            params = sigalgo["parameters"]
            mgf_hash_cls = self._resolve_hash_cls(
                params["mask_gen_algorithm"]["parameters"]["algorithm"].native
            )
            public_key.verify(
                signature,
                data,
                padding.PSS(padding.MGF1(mgf_hash_cls()), params["salt_length"].native),
                hash_cls(),
            )
        elif sigalgo.signature_algo == "rsassa_pkcs1v15":
            public_key.verify(signature, data, padding.PKCS1v15(), hash_cls())
        else:
            raise SignatureVerificationError(
                f"Unsupported signature algorithm: {sigalgo['algorithm'].native}"
            )

    @staticmethod
    def _issued_by(cert: cx509.Certificate, issuer: cx509.Certificate) -> bool:
        try:
            cert.verify_directly_issued_by(issuer)
            return True
        except (InvalidSignature, TypeError, ValueError):
            return False

    def _ocsp_responder(
        self,
        basic: ocsp.BasicOCSPResponse,
        issuer: cx509.Certificate,
        othercerts: list[x509.Certificate],
    ) -> tuple[cx509.Certificate | None, str | None]:
        """Find the certificate which signed the OCSP response (RFC 6960 4.2.2.2).

        Returns:
            (responder certificate, None) or (None, error message).
        """
        responder_id = basic["tbs_response_data"]["responder_id"]

        def matches(candidate: x509.Certificate) -> bool:
            if responder_id.name == "by_name":
                return candidate.subject == responder_id.chosen
            return candidate.public_key.sha1 == responder_id.chosen.native

        # response signed directly by the issuing CA
        if matches(self._to_asn1(issuer)):
            return issuer, None

        # delegated responder: must be issued by the CA and carry id-kp-OCSPSigning
        for candidate in basic["certs"] or []:
            if not matches(candidate):
                continue
            eku = candidate.extended_key_usage_value
            if eku is None or "ocsp_signing" not in eku.native:
                return None, "responder certificate is not authorized for OCSP signing"
            responder = self._to_cryptography(candidate)
            if not self._issued_by(responder, issuer):
                return None, "responder certificate is not issued by certificate issuer"
            if not self.validate_certificate(
                responder,
                [*othercerts, issuer],
                extended_key_usage=["ocsp_signing"],
            ):
                return None, "signing certificate validation failed"
            return responder, None
        return None, "signing certificate not found"

    def verify_ocsp_data(self, result: Result) -> None:
        if result.crldata.native is None:
            result.ocsp_result(None, None, "no OCSP data found")
            return
        cert = result.cert
        othercerts = result.othercerts
        crldata = result.crldata
        issuer_cert = self._find_issuer(cert, othercerts)
        if issuer_cert is None:
            result.ocsp_result(False, None, "cannot resolve issuer certificate")
            return

        if len(crldata) != 1:
            result.ocsp_result(False, None, "unsupported number of OCSP responses")
            return
        crl1 = crldata[0]
        if crl1.native.get("other_rev_info_format") != "ocsp_response":
            result.ocsp_result(False, None, "bad ocsp data")
            return
        ocsp_resp: ocsp.OCSPResponse = crl1.chosen["other_rev_info"]
        if ocsp_resp["response_status"].native != "successful":
            result.ocsp_result(False, None, "ocsp response status failure")
            return
        if ocsp_resp["response_bytes"]["response_type"].native != "basic_ocsp_response":
            result.ocsp_result(False, None, "unknown response type")
            return
        basic: ocsp.BasicOCSPResponse = ocsp_resp.basic_ocsp_response
        tbs = basic["tbs_response_data"]

        issuer = self._to_cryptography(issuer_cert)
        if not self._issued_by(self._to_cryptography(cert), issuer):
            result.ocsp_result(False, None, "cannot resolve issuer certificate")
            return

        responder, msg = self._ocsp_responder(basic, issuer, othercerts)
        if responder is None:
            result.ocsp_result(False, None, msg)
            return
        try:
            self._verify_signature(
                responder.public_key(),
                basic["signature"].native,
                tbs.dump(),
                basic["signature_algorithm"],
            )
        except (
            InvalidSignature,
            TypeError,
            ValueError,
            HashAlgorithmError,
            SignatureVerificationError,
        ) as exc:
            logger.debug("OCSP signature verification failed: %s", exc)
            result.ocsp_result(False, None, "signing certificate is invalid")
            return

        single = None
        for response in tbs["responses"]:
            cert_id = response["cert_id"]
            if cert_id[
                "serial_number"
            ].native == cert.serial_number and self._verify_ocsp_cert_id(
                cert_id, issuer
            ):
                single = response
                break
        if single is None:
            result.ocsp_result(False, None, "response not for signing certificate")
            return

        produced_at = tbs["produced_at"].native
        this_update = single["this_update"].native
        next_update = single["next_update"].native
        now = datetime.datetime.now(datetime.UTC)
        if produced_at > now:
            result.ocsp_result(False, None, "value of produced_at is in the future")
            return
        if this_update > now:
            result.ocsp_result(False, None, "value of this_update is in the future")
            return
        if next_update is not None and next_update < now:
            result.ocsp_result(False, None, "response is stale")
            return

        status = single["cert_status"]
        if status.name == "revoked":
            revoked_at = status.chosen["revocation_time"].native
            result.ocsp_result(False, None, f"certificate revoked at {revoked_at}")
            return
        if status.name != "good":
            result.ocsp_result(False, None, "certificate status unknown")
            return
        result.ocsp_result(True, (produced_at, next_update), "valid")

    def _tst_imprint_matches(self, tst: tsp.TSTInfo, data: bytes) -> bool:
        """Check the TSTInfo message imprint, using the hash algorithm it names."""
        imprint = tst["message_imprint"]
        hash_name = imprint["hash_algorithm"]["algorithm"].native
        try:
            hash_cls = self._resolve_hash_cls(hash_name)
        except HashAlgorithmError as exc:
            raise TSPVerificationError(
                f"Unsupported TSP message imprint hash algorithm: {hash_name}"
            ) from exc
        digest = hashes.Hash(hash_cls())
        digest.update(data)
        return digest.finalize() == imprint["hashed_message"].native

    def verify_tsp_data(self, result: Result, datau: bytes | None = None):
        """Verify the timestamp token of ``result``.

        Args:
            datau: Timestamped content, needed for a document timestamp
                (``result.signed_data`` is None), whose imprint covers the
                content instead of a signature.
        """
        if result.tsp_data is None:
            result.tsp_result(None, None, "no TSP data found")
            return
        if result.tsp_data["encap_content_info"]["content_type"].native != "tst_info":
            raise TSPVerificationError(
                f"Unsupported TSP content type: {result.tsp_data['encap_content_info']['content_type'].native}"
            )
        if result.tsp_data["encap_content_info"]["content"].native["version"] != "v1":
            raise TSPVerificationError(
                f"Unsupported TSP content version: {result.tsp_data['encap_content_info']['content'].native['version']}"
            )

        sub = self.decompose_signed_data(result.tsp_data, b"")
        if not sub.hashok:
            # the signature covers only the signed attributes; without this the
            # TSTInfo, and so the imprint and time, could be swapped freely
            result.tsp_result(False, None, "TSP message digest is invalid")
            return
        if not sub.signatureok:
            result.tsp_result(False, None, "TSP signature is invalid")
            return

        try:
            self._verify_certificate(
                sub.cert,
                sub.othercerts,
                extended_key_usage={"time_stamping"},
            )
        except verification.VerificationError as exc:
            raise TSPVerificationError(
                f"TSP certificate path validation error: {exc}"
            ) from exc
        except ValueError as exc:
            raise TSPVerificationError(
                f"TSP certificate validation error: {exc}"
            ) from exc

        tst = result.tsp_data["encap_content_info"]["content"].parsed
        gen_time = tst["gen_time"].native
        tsa_cert = self._to_cryptography(sub.cert)
        if not tsa_cert.not_valid_before_utc <= gen_time <= tsa_cert.not_valid_after_utc:
            # the signer's certificate is validated at this time, which the
            # TSA can only vouch for while its own certificate is valid
            result.tsp_result(
                False, None, "TSP time is outside the TSA certificate validity"
            )
            return

        # verify the message imprint against the signature, or against the
        # document itself for a document timestamp without signed data
        if result.signed_data is not None:
            timestamped = result.signed_data["signer_infos"][0]["signature"].native
        elif datau is not None:
            timestamped = datau
        else:
            result.tsp_result(False, None, "no timestamped data to check against")
            return
        if self._tst_imprint_matches(tst, timestamped):
            result.tsp_result(True, gen_time, "valid")
        else:
            result.tsp_result(False, None, "Invalid hash value")

    def verify_certificate_data(self, result: Result) -> None:
        """Validate the signer's certificate path, once TSP data is verified.

        A valid timestamp proves the signature existed at its time, so the
        path is validated for that time: a certificate which expired since
        still verifies. Without a valid timestamp it is validated for now.
        Revocation is reported separately, by :meth:`verify_ocsp_data`.
        """
        if result.tspok is True:
            result.certtime = result.tspdata
        else:
            result.certtime = datetime.datetime.now(datetime.UTC)
        result.certok = self.validate_certificate(
            result.cert, result.othercerts, validation_time=result.certtime
        )

    def verify_data(self, datas: bytes, datau: bytes) -> Result:
        """Verify a signed payload against its original content.

        Args:
            datas: Signed CMS payload to verify.
            datau: Original unsigned content bytes.

        Returns:
            Verification result object.
        """
        result = self.decompose_signed_data(datas, datau)
        self.verify_tsp_data(result)
        self.verify_certificate_data(result)
        self.verify_ocsp_data(result)

        return result


def verify(
    datas: bytes,
    datau: bytes,
    trusted_certs: list[bytes | x509.Certificate] | None = None,
) -> Result:
    """Verify a signed payload using the supplied trusted certificates.

    Args:
        datas: Signed CMS payload to verify.
        datau: Original unsigned content bytes.
        trusted_certs: Optional trusted certificate list for chain validation.

    Returns:
        Verification result object.
    """
    cls = SignatureVerifier(trusted_certs)
    return cls.verify_data(datas, datau)
