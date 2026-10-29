import datetime
import hashlib
import unittest
from types import SimpleNamespace
from unittest import mock

from asn1crypto import cms as asn1_cms, ocsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp as cx_ocsp, verification
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from endesive import verifier as generic_verifier
from endesive.exceptions import (
    HashAlgorithmError,
    SignatureVerificationError,
    TSPVerificationError,
)
from endesive.pdf.verify import PDFVerifier, verify as pdf_verify


class SecurityVerifierTests(unittest.TestCase):
    class _Native:
        def __init__(self, value):
            self.native = value

    class _FakeRevocationInfoChoices(list):
        def __init__(self, items, native):
            super().__init__(items)
            self.native = native

    def _build_chain(self):
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Issuer CA")])
        now = datetime.datetime.now(datetime.UTC)

        issuer_cert = (
            x509.CertificateBuilder()
            .subject_name(issuer_name)
            .issuer_name(issuer_name)
            .public_key(issuer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(leaf_name)
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

        return issuer_cert, leaf_cert

    def test_pdf_verifier_checks_ocsp_cert_id_hashes(self):
        issuer_cert, leaf_cert = self._build_chain()
        verifier = PDFVerifier(b"%PDF-1.7\n")

        issuer_asn1 = asn1_x509.Certificate.load(
            issuer_cert.public_bytes(serialization.Encoding.DER)
        )
        issuer_name_der = issuer_asn1["tbs_certificate"]["subject"].dump()
        issuer_key_bits = issuer_asn1["tbs_certificate"]["subject_public_key_info"]["public_key"].contents[1:]

        cert_id = ocsp.CertId(
            {
                "hash_algorithm": {"algorithm": "sha1"},
                "issuer_name_hash": hashlib.sha1(issuer_name_der).digest(),
                "issuer_key_hash": hashlib.sha1(issuer_key_bits).digest(),
                "serial_number": leaf_cert.serial_number,
            }
        )
        bad_cert_id = ocsp.CertId(
            {
                "hash_algorithm": {"algorithm": "sha1"},
                "issuer_name_hash": hashlib.sha1(issuer_name_der).digest(),
                "issuer_key_hash": b"\x00" * 20,
                "serial_number": leaf_cert.serial_number,
            }
        )

        self.assertTrue(verifier._verify_ocsp_cert_id(cert_id, issuer_cert))
        self.assertFalse(verifier._verify_ocsp_cert_id(bad_cert_id, issuer_cert))

    def test_pdf_verify_rejects_invalid_signature_delimiters(self):
        malformed = b"%PDF-1.7\n/ByteRange [0 1 2 3]\nabcdef"
        with self.assertRaises(ValueError):
            pdf_verify(malformed)

    def _signed_data(self, data, key=None, cert=None, options=(), padding_=None):
        if key is None:
            cert, key = self._make_cert("Signer")
        builder = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(data)
            .add_signer(cert, key, hashes.SHA256(), rsa_padding=padding_)
        )
        der = builder.sign(
            serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary, *options]
        )
        return der, cert

    def test_generic_verifier_decompose_signed_data_variants(self):
        verifier = generic_verifier.SignatureVerifier()
        data = b"payload to sign"
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC")]))
            .public_key(ec_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1)
            )
            .sign(ec_key, hashes.SHA256())
        )
        pss = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)
        detached = [pkcs7.PKCS7Options.DetachedSignature]

        cases = [
            ("rsa signed attrs", {"options": detached}, data),
            (
                "rsa no attrs",
                {"options": [*detached, pkcs7.PKCS7Options.NoAttributes]},
                data,
            ),
            ("rsa pss", {"options": detached, "padding_": pss}, data),
            ("ecdsa", {"key": ec_key, "cert": ec_cert, "options": detached}, data),
            ("encapsulated content", {}, b""),
        ]
        for label, kwargs, datau in cases:
            with self.subTest(label):
                der, cert = self._signed_data(data, **kwargs)
                result = verifier.decompose_signed_data(der, datau)
                self.assertTrue(result.hashok)
                self.assertTrue(result.signatureok)
                self.assertEqual(
                    result.cert.dump(), cert.public_bytes(serialization.Encoding.DER)
                )

        der, _ = self._signed_data(data, options=detached)
        result = verifier.decompose_signed_data(der, b"tampered payload")
        self.assertFalse(result.hashok)
        self.assertTrue(result.signatureok)

        der, _ = self._signed_data(
            data, options=[*detached, pkcs7.PKCS7Options.NoAttributes]
        )
        result = verifier.decompose_signed_data(der, b"tampered payload")
        self.assertFalse(result.signatureok)

    def _with_certificates(self, der, certs):
        signed_data = asn1_cms.ContentInfo.load(der)["content"]
        signed_data["certificates"] = asn1_cms.CertificateSet(
            [
                asn1_cms.CertificateChoices(
                    name="certificate",
                    value=asn1_x509.Certificate.load(
                        c.public_bytes(serialization.Encoding.DER)
                    ),
                )
                for c in certs
            ]
        )
        return signed_data

    def test_generic_verifier_raises_on_duplicate_signer_certificate(self):
        verifier = generic_verifier.SignatureVerifier()
        der, cert = self._signed_data(b"payload")

        with self.assertRaises(SignatureVerificationError):
            verifier.decompose_signed_data(
                self._with_certificates(der, [cert, cert]), b"payload"
            )

    def test_generic_verifier_raises_when_signer_certificate_missing(self):
        verifier = generic_verifier.SignatureVerifier()
        der, cert = self._signed_data(b"payload")
        other, _ = self._make_cert("Other")

        with self.assertRaises(SignatureVerificationError):
            verifier.decompose_signed_data(
                self._with_certificates(der, [other]), b"payload"
            )

        # same serial number from a different issuer is not the signer
        impostor_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        impostor_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Impostor")])
        impostor = (
            x509.CertificateBuilder()
            .subject_name(cert.subject)
            .issuer_name(impostor_name)
            .public_key(impostor_key.public_key())
            .serial_number(cert.serial_number)
            .not_valid_before(cert.not_valid_before_utc)
            .not_valid_after(cert.not_valid_after_utc)
            .sign(impostor_key, hashes.SHA256())
        )
        with self.assertRaises(SignatureVerificationError):
            verifier.decompose_signed_data(
                self._with_certificates(der, [impostor]), b"payload"
            )

    def test_generic_verifier_resolve_hash_cls_handles_common_algorithms(self):
        verifier = generic_verifier.SignatureVerifier()

        self.assertIs(verifier._resolve_hash_cls("sha256"), hashes.SHA256)
        self.assertIs(verifier._resolve_hash_cls("sha256RSA"), hashes.SHA256)
        self.assertIs(verifier._resolve_hash_cls("sha384"), hashes.SHA384)

        with self.assertRaises(HashAlgorithmError):
            verifier._resolve_hash_cls(None)

        with self.assertRaises(HashAlgorithmError):
            verifier._resolve_hash_cls("not-supported")

    def test_generic_verifier_validate_certificate_handles_validator_errors(self):
        verifier = generic_verifier.SignatureVerifier()
        _, leaf_cert = self._build_chain()

        for exc in (
            verification.VerificationError("path validation"),
            ValueError("validation"),
        ):
            validator = mock.Mock()
            validator.verify.side_effect = exc
            with mock.patch.object(verifier, "_validator", return_value=validator):
                self.assertFalse(verifier.validate_certificate(leaf_cert))

    def test_generic_verifier_validate_certificate_builds_chain(self):
        issuer_cert, leaf_cert = self._build_chain()
        leaf_asn1 = asn1_x509.Certificate.load(
            leaf_cert.public_bytes(serialization.Encoding.DER)
        )
        issuer_pem = issuer_cert.public_bytes(serialization.Encoding.PEM)

        trusting = generic_verifier.SignatureVerifier([issuer_pem])
        self.assertTrue(trusting.validate_certificate(leaf_asn1))
        self.assertTrue(trusting.validate_certificate(leaf_cert))

        untrusting = generic_verifier.SignatureVerifier()
        self.assertFalse(untrusting.validate_certificate(leaf_asn1))

        # leaf has neither keyUsage nor extendedKeyUsage extension
        self.assertFalse(
            trusting.validate_certificate(leaf_asn1, key_usage=["digital_signature"])
        )
        self.assertFalse(
            trusting.validate_certificate(
                leaf_asn1, extended_key_usage=["time_stamping"]
            )
        )

    def test_generic_verifier_check_usage_maps_asn1crypto_names(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        check = generic_verifier.SignatureVerifier._check_usage

        check(cert, {"digital_signature", "non_repudiation"}, {"time_stamping"})
        check(cert, None, {"1.3.6.1.5.5.7.3.8"})
        with self.assertRaises(ValueError):
            check(cert, {"key_cert_sign"}, None)
        with self.assertRaises(ValueError):
            check(cert, None, {"ocsp_signing"})

    def test_generic_verifier_verify_ocsp_data_handles_known_failure_modes(self):
        verifier = generic_verifier.SignatureVerifier()
        issuer = object()
        cert = SimpleNamespace(issuer=issuer, serial_number=7)

        result = generic_verifier.Result(
            mock.Mock(),
            SimpleNamespace(native=None),
            cert,
            [],
            True,
            True,
        )
        verifier.verify_ocsp_data(result)
        self.assertIsNone(result.ocspok)
        self.assertEqual(result.ocspmsg, "no OCSP data found")

        result = generic_verifier.Result(
            mock.Mock(),
            self._FakeRevocationInfoChoices(
                [SimpleNamespace(native={"other_rev_info_format": "ocsp_response"})],
                {"other_rev_info_format": "ocsp_response"},
            ),
            cert,
            [],
            True,
            True,
        )
        verifier.verify_ocsp_data(result)
        self.assertFalse(result.ocspok)
        self.assertEqual(result.ocspmsg, "cannot resolve issuer certificate")

        result = generic_verifier.Result(
            mock.Mock(),
            self._FakeRevocationInfoChoices(
                [
                    SimpleNamespace(native={"other_rev_info_format": "ocsp_response"}),
                    SimpleNamespace(native={"other_rev_info_format": "ocsp_response"}),
                ],
                {"other_rev_info_format": "ocsp_response"},
            ),
            cert,
            [SimpleNamespace(subject=issuer)],
            True,
            True,
        )
        verifier.verify_ocsp_data(result)
        self.assertFalse(result.ocspok)
        self.assertEqual(result.ocspmsg, "unsupported number of OCSP responses")

        result = generic_verifier.Result(
            mock.Mock(),
            self._FakeRevocationInfoChoices(
                [SimpleNamespace(native={"other_rev_info_format": "bad"})],
                {"other_rev_info_format": "bad"},
            ),
            cert,
            [SimpleNamespace(subject=issuer)],
            True,
            True,
        )
        verifier.verify_ocsp_data(result)
        self.assertFalse(result.ocspok)
        self.assertEqual(result.ocspmsg, "bad ocsp data")

    def _make_cert(self, name, issuer=None, issuer_key=None, ca=False, eku=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=ca, path_length=None), critical=True
            )
        )
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        return builder.sign(issuer_key or key, hashes.SHA256()), key

    def _ocsp_result(
        self,
        leaf,
        issuer,
        signer,
        signer_key,
        status=cx_ocsp.OCSPCertStatus.GOOD,
        next_update_delta=datetime.timedelta(days=1),
        include_signer=False,
        tamper=False,
    ):
        now = datetime.datetime.now(datetime.UTC)
        builder = (
            cx_ocsp.OCSPResponseBuilder()
            .add_response(
                cert=leaf,
                issuer=issuer,
                algorithm=hashes.SHA1(),
                cert_status=status,
                this_update=now - datetime.timedelta(minutes=5),
                next_update=now + next_update_delta,
                revocation_time=(
                    now - datetime.timedelta(hours=1)
                    if status == cx_ocsp.OCSPCertStatus.REVOKED
                    else None
                ),
                revocation_reason=None,
            )
            .responder_id(cx_ocsp.OCSPResponderEncoding.HASH, signer)
        )
        if include_signer:
            builder = builder.certificates([signer])
        response = builder.sign(signer_key, hashes.SHA256())
        der = response.public_bytes(serialization.Encoding.DER)
        if tamper:
            # without embedded certificates the signature ends the structure
            der = der[:-1] + bytes([der[-1] ^ 0x01])
        crls = asn1_cms.RevocationInfoChoices(
            [
                asn1_cms.RevocationInfoChoice(
                    name="other",
                    value=asn1_cms.OtherRevocationInfoFormat(
                        {
                            "other_rev_info_format": "ocsp_response",
                            "other_rev_info": ocsp.OCSPResponse.load(der),
                        }
                    ),
                )
            ]
        )

        def asn1(c):
            return asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))

        return generic_verifier.Result(
            mock.Mock(), crls, asn1(leaf), [asn1(issuer)], True, True
        )

    def test_generic_verifier_verify_ocsp_data_validates_responses(self):
        root, root_key = self._make_cert("Root", ca=True)
        leaf, _ = self._make_cert("Leaf", root, root_key)
        responder, responder_key = self._make_cert(
            "Responder", root, root_key, eku=[ExtendedKeyUsageOID.OCSP_SIGNING]
        )
        no_eku, no_eku_key = self._make_cert("NoEku", root, root_key)
        other_root, other_key = self._make_cert("Other", ca=True)
        foreign, foreign_key = self._make_cert(
            "Foreign", other_root, other_key, eku=[ExtendedKeyUsageOID.OCSP_SIGNING]
        )
        verifier = generic_verifier.SignatureVerifier(
            [root.public_bytes(serialization.Encoding.PEM)]
        )

        cases = [
            ("ca signed", {"signer": root, "signer_key": root_key}, True, "valid"),
            (
                "delegated",
                {"signer": responder, "signer_key": responder_key, "include_signer": True},
                True,
                "valid",
            ),
            (
                "revoked",
                {
                    "signer": root,
                    "signer_key": root_key,
                    "status": cx_ocsp.OCSPCertStatus.REVOKED,
                },
                False,
                "certificate revoked at",
            ),
            (
                "unknown",
                {
                    "signer": root,
                    "signer_key": root_key,
                    "status": cx_ocsp.OCSPCertStatus.UNKNOWN,
                },
                False,
                "certificate status unknown",
            ),
            (
                "stale",
                {
                    "signer": root,
                    "signer_key": root_key,
                    "next_update_delta": -datetime.timedelta(minutes=1),
                },
                False,
                "response is stale",
            ),
            (
                "delegated without ocsp eku",
                {"signer": no_eku, "signer_key": no_eku_key, "include_signer": True},
                False,
                "responder certificate is not authorized for OCSP signing",
            ),
            (
                "foreign responder",
                {"signer": foreign, "signer_key": foreign_key, "include_signer": True},
                False,
                "responder certificate is not issued by certificate issuer",
            ),
            (
                "responder certificate missing",
                {"signer": responder, "signer_key": responder_key},
                False,
                "signing certificate not found",
            ),
            (
                "tampered signature",
                {"signer": root, "signer_key": root_key, "tamper": True},
                False,
                "signing certificate is invalid",
            ),
        ]
        for label, kwargs, ok, msg in cases:
            with self.subTest(label):
                result = self._ocsp_result(leaf, root, **kwargs)
                verifier.verify_ocsp_data(result)
                self.assertIs(result.ocspok, ok)
                self.assertTrue(result.ocspmsg.startswith(msg), result.ocspmsg)

    def test_generic_verifier_verify_tsp_data_rejects_invalid_payloads(self):
        verifier = generic_verifier.SignatureVerifier()
        result = generic_verifier.Result(
            mock.Mock(),
            mock.Mock(),
            mock.Mock(),
            [],
            True,
            True,
        )

        result.tsp_data = {
            "encap_content_info": {
                "content_type": self._Native("not_tst_info"),
                "content": self._Native({"version": "v1"}),
            }
        }
        with self.assertRaises(TSPVerificationError):
            verifier.verify_tsp_data(result)

        result.tsp_data = {
            "encap_content_info": {
                "content_type": self._Native("tst_info"),
                "content": self._Native({"version": "v2"}),
            }
        }
        with self.assertRaises(TSPVerificationError):
            verifier.verify_tsp_data(result)

    def test_generic_verifier_verify_data_calls_all_substeps(self):
        verifier = generic_verifier.SignatureVerifier()
        result = mock.Mock()

        with mock.patch.object(verifier, "decompose_signed_data", return_value=result), \
             mock.patch.object(verifier, "validate_certificate", return_value=True) as validate_mock, \
             mock.patch.object(verifier, "verify_ocsp_data") as ocsp_mock, \
             mock.patch.object(verifier, "verify_tsp_data") as tsp_mock:
            returned = verifier.verify_data(b"cms", b"payload")

        self.assertIs(returned, result)
        validate_mock.assert_called_once_with(result.cert, result.othercerts)
        ocsp_mock.assert_called_once_with(result)
        tsp_mock.assert_called_once_with(result)


if __name__ == "__main__":
    unittest.main()
