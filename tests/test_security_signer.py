import datetime
import inspect
import unittest
from types import SimpleNamespace
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    NameOID,
    ObjectIdentifier,
)
from fake_tsa import FakeTSA

from endesive import email, plain, signer, verifier
from endesive.exceptions import HashAlgorithmError
from endesive.pdf import cms as pdf_cms


class SecuritySignerTests(unittest.TestCase):
    def _build_ec_chain(self):
        now = datetime.datetime.now(datetime.UTC)
        ca_key = ec.generate_private_key(ec.SECP384R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA384())
        )
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EC Leaf")])
            )
            .issuer_name(ca_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA384())
        )
        return ca_cert, leaf_key, leaf_cert

    def test_sign_ec_key_uses_ecdsa_signature_algorithm(self):
        ca_cert, leaf_key, leaf_cert = self._build_ec_chain()

        for hashalgo, expected in (
            ("sha256", "sha256_ecdsa"),
            ("sha384", "sha384_ecdsa"),
            ("sha512", "sha512_ecdsa"),
        ):
            for attrs in (True, False):
                with self.subTest(hashalgo=hashalgo, attrs=attrs):
                    cms_bytes = signer.sign(
                        b"payload",
                        leaf_key,
                        leaf_cert,
                        [ca_cert],
                        hashalgo,
                        attrs=attrs,
                    )
                    signer_info = signer.cms.ContentInfo.load(cms_bytes)["content"][
                        "signer_infos"
                    ][0]
                    self.assertEqual(
                        signer_info["signature_algorithm"]["algorithm"].native,
                        expected,
                    )
                    result = verifier.verify(
                        cms_bytes, b"payload", [ca_cert.public_bytes(Encoding.PEM)]
                    )
                    self.assertTrue(result.hashok)
                    self.assertTrue(result.signatureok)
                    self.assertTrue(result.certok)

    def _build_eddsa_chain(self, leaf_key):
        now = datetime.datetime.now(datetime.UTC)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RSA CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "EdDSA Leaf")])
            )
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        return ca_cert, leaf_cert

    def test_sign_ed25519_key(self):
        leaf_key = ed25519.Ed25519PrivateKey.generate()
        issuer_cert, leaf_cert = self._build_eddsa_chain(leaf_key)

        cms_bytes = signer.sign(
            b"payload", leaf_key, leaf_cert, [issuer_cert], "sha512"
        )
        signer_info = signer.cms.ContentInfo.load(cms_bytes)["content"][
            "signer_infos"
        ][0]
        self.assertEqual(
            signer_info["signature_algorithm"]["algorithm"].native, "ed25519"
        )
        self.assertEqual(signer_info["digest_algorithm"]["algorithm"].native, "sha512")
        result = verifier.verify(
            cms_bytes, b"payload", [issuer_cert.public_bytes(Encoding.PEM)]
        )
        self.assertTrue(result.hashok)
        self.assertTrue(result.signatureok)
        self.assertTrue(result.certok)

    def test_sign_eddsa_rejects_invalid_parameters(self):
        leaf_key = ed25519.Ed25519PrivateKey.generate()
        issuer_cert, leaf_cert = self._build_eddsa_chain(leaf_key)

        with self.assertRaises(HashAlgorithmError):
            signer.sign(b"payload", leaf_key, leaf_cert, [issuer_cert], "sha256")
        with self.assertRaises(signer.SignerError):
            signer.sign(
                b"payload", leaf_key, leaf_cert, [issuer_cert], "sha512", pss=True
            )
        with self.assertRaises(signer.SignerError):
            signer.sign(
                b"payload", leaf_key, leaf_cert, [issuer_cert], "sha512", attrs=False
            )

        ed448_key = ed448.Ed448PrivateKey.generate()
        _, ed448_cert = self._build_eddsa_chain(ed448_key)
        with self.assertRaises(signer.SignerError):
            signer.sign(b"payload", ed448_key, ed448_cert, [issuer_cert], "sha512")

    def test_sign_ec_key_rejects_pss_and_unsupported_hash(self):
        ca_cert, leaf_key, leaf_cert = self._build_ec_chain()

        with self.assertRaises(signer.SignerError):
            signer.sign(b"payload", leaf_key, leaf_cert, [ca_cert], "sha256", pss=True)
        with self.assertRaises(HashAlgorithmError):
            signer.sign(b"payload", leaf_key, leaf_cert, [ca_cert], "md5")

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

    def test_default_hash_algorithms_are_sha256(self):
        self.assertEqual(inspect.signature(plain.sign).parameters["hashalgo"].default, "sha256")
        self.assertEqual(inspect.signature(email.sign).parameters["hashalgo"].default, "sha256")
        self.assertEqual(inspect.signature(pdf_cms.sign).parameters["algomd"].default, "sha256")
        self.assertEqual(inspect.signature(pdf_cms.timestamp).parameters["algomd"].default, "sha256")

    def test_pdf_cms_sign_uses_tsp_and_ocsp_options_keywords(self):
        sign_params = inspect.signature(pdf_cms.sign).parameters

        self.assertIn("tspurl", sign_params)
        self.assertIn("tspoptions", sign_params)
        self.assertIn("ocspoptions", sign_params)
        self.assertNotIn("timestampurl", sign_params)
        self.assertNotIn("timestampcredentials", sign_params)
        self.assertNotIn("timestamp_req_options", sign_params)
        self.assertNotIn("ocspissuer", sign_params)

    def test_pdf_cms_timestamp_uses_tsp_keywords(self):
        timestamp_params = inspect.signature(pdf_cms.timestamp).parameters

        self.assertIn("tspurl", timestamp_params)
        self.assertIn("tspoptions", timestamp_params)
        self.assertNotIn("timestampurl", timestamp_params)
        self.assertNotIn("timestampcredentials", timestamp_params)
        self.assertNotIn("timestamp_req_options", timestamp_params)

    def test_pdf_cms_sign_rejects_legacy_timestamp_kwargs(self):
        issuer_cert, leaf_cert = self._build_chain()
        with self.assertRaises(TypeError):
            pdf_cms.sign(
                b"%PDF-1.4\n",  # type: ignore[arg-type]
                {},
                key=None,
                cert=leaf_cert,
                othercerts=[issuer_cert],
                timestampurl="https://tsa.example",
            )

    def test_fetch_ocsp_response_sets_timeout_and_handles_request_error(self):
        issuer_cert, leaf_cert = self._build_chain()

        with mock.patch(
            "endesive.signer.requests.post",
            side_effect=requests.exceptions.Timeout("timeout"),
        ) as post_mock:
            ocspoptions = {
                'issuer': issuer_cert
            }
            result = signer.fetch_ocsp_response(leaf_cert, "https://ocsp.example", ocspoptions)

        self.assertIsNone(result)

    def test_fetch_ocsp_response_returns_none_on_http_error(self):
        issuer_cert, leaf_cert = self._build_chain()
        fake_response = SimpleNamespace(status_code=503, content=b"")

        with mock.patch("endesive.signer.requests.post", return_value=fake_response) as post_mock:
            ocspoptions = {
                'issuer': issuer_cert
            }
            result = signer.fetch_ocsp_response(leaf_cert, "https://ocsp.example", ocspoptions)

        self.assertIsNone(result)

    def test_fetch_ocsp_response_forwards_request_options(self):
        issuer_cert, leaf_cert = self._build_chain()
        ok_response = SimpleNamespace(status_code=200, content=b"ocsp-ok")

        with mock.patch("endesive.signer.requests.post", return_value=ok_response) as post_mock:
            result = signer.fetch_ocsp_response(
                leaf_cert,
                "https://ocsp.example",
                {
                    "issuer": issuer_cert,
                    "timeout": 3,
                    "verify": False,
                },
            )

        self.assertEqual(result, b"ocsp-ok")
        self.assertEqual(post_mock.call_args.kwargs["timeout"], 3)
        self.assertEqual(post_mock.call_args.kwargs["verify"], False)
        self.assertNotIn("issuer", post_mock.call_args.kwargs)

    def test_fetch_ocsp_response_returns_none_without_issuer(self):
        _, leaf_cert = self._build_chain()
        self.assertIsNone(
            signer.fetch_ocsp_response(
                leaf_cert,
                "https://ocsp.example",
                {"verify": False},
            )
        )

    def test_fetch_ocsp_response_sets_default_timeout(self):
        issuer_cert, leaf_cert = self._build_chain()
        ok_response = SimpleNamespace(status_code=200, content=b"ok")

        with mock.patch("endesive.signer.requests.post", return_value=ok_response) as post_mock:
            signer.fetch_ocsp_response(
                leaf_cert,
                "https://ocsp.example",
                {"issuer": issuer_cert},
            )

        self.assertEqual(post_mock.call_args.kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)

    def test_fetch_request_options_are_not_mutated(self):
        issuer_cert, leaf_cert = self._build_chain()
        ocsp_options = {"issuer": issuer_cert, "verify": False}
        tsp_options = {"verify": False, "username": "user", "password": "pass"}

        with mock.patch("endesive.signer.requests.post", return_value=SimpleNamespace(status_code=200, content=b"ok", headers={"Content-Type": "application/ocsp-response"})):
            signer.fetch_ocsp_response(leaf_cert, "https://ocsp.example", ocsp_options)
        with mock.patch("endesive.signer.requests.post", side_effect=FakeTSA().post):
            signer.fetch_tsp_response(b"payload", "sha256", "https://tsa.example", tsp_options)

        self.assertIn("issuer", ocsp_options)
        self.assertIn("username", tsp_options)
        self.assertIn("password", tsp_options)

    def test_fetch_tsp_response_sets_timeout_auth_and_rejects_invalid_http_status(self):
        payload = b"payload"

        with mock.patch("endesive.signer.requests.post", side_effect=FakeTSA().post) as post_mock:
            result = signer.fetch_tsp_response(
                payload,
                "sha256",
                "https://tsa.example",
                {"verify": False, "username": "user", "password": "pass"},
            )

        self.assertTrue(signer.tsp_granted(signer.tsp.TimeStampResp.load(result)))
        self.assertEqual(post_mock.call_args.kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)
        self.assertTrue(post_mock.call_args.kwargs["headers"]["Authorization"].startswith("Basic "))

        bad_response = SimpleNamespace(status_code=503, headers={}, content=b"nope")
        with mock.patch("endesive.signer.requests.post", return_value=bad_response):
            self.assertIsNone(
                signer.fetch_tsp_response(
                    payload,
                    "sha256",
                    "https://tsa.example",
                    None,
                    None,
                )
            )

        wrong_content_type = SimpleNamespace(
            status_code=200,
            headers={"Content-Type": "application/json"},
            content=b"bad",
        )
        with mock.patch("endesive.signer.requests.post", return_value=wrong_content_type):
            self.assertIsNone(
                signer.fetch_tsp_response(
                    payload,
                    "sha256",
                    "https://tsa.example",
                    None,
                    None,
                )
            )

    def test_signer_rejects_invalid_attrs_and_hashalgo(self):
        _, leaf_cert = self._build_chain()

        with self.assertRaises(signer.SignerError):
            signer.Signer(
                b"payload",
                key=None,
                cert=leaf_cert,
                othercerts=[],
                hashalgo="sha256",
                attrs="nope",
                signed_value=None,
                hsm=None,
                pss=False,
                tspurl=None,
                tspoptions=None,
                ocspurl=None,
                ocspoptions=None,
            )

        with self.assertRaises(signer.HashAlgorithmError):
            signer.Signer(
                b"payload",
                key=None,
                cert=leaf_cert,
                othercerts=[],
                hashalgo="sha999",
                attrs=True,
                signed_value=None,
                hsm=None,
                pss=False,
                tspurl=None,
                tspoptions=None,
                ocspurl=None,
                ocspoptions=None,
            )

    def test_signer_accepts_callable_attrs_and_custom_signed_value(self):
        issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        principal = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")])
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
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(principal)
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

        def attrs_builder(value):
            return ["custom-attr", value]

        signer_obj = signer.Signer(
            b"payload",
            key=leaf_key,
            cert=leaf_cert,
            othercerts=[issuer_cert],
            hashalgo="sha256",
            attrs=attrs_builder,
            signed_value=b"custom-signed-value",
            hsm=None,
            pss=False,
            tspurl=None,
            tspoptions=None,
            ocspurl=None,
            ocspoptions=None,
        )

        self.assertIsNotNone(signer_obj.attrs)
        self.assertEqual(signer_obj.signed_value, b"custom-signed-value")
        self.assertTrue(callable(signer_obj.attrs))

    def test_fetch_tsp_response_handles_empty_credentials_and_prehashed_data(self):
        tsa = FakeTSA()

        with mock.patch("endesive.signer.requests.post", side_effect=tsa.post) as post_mock:
            result = signer.fetch_tsp_response(
                b"payload",
                "sha256",
                "https://tsa.example",
                {"verify": False},
                prehashed=b"x" * 32,
            )

        self.assertTrue(signer.tsp_granted(signer.tsp.TimeStampResp.load(result)))
        self.assertEqual(tsa.requests[0]["message_imprint"]["hashed_message"].native, b"x" * 32)
        self.assertNotIn("Authorization", post_mock.call_args.kwargs["headers"])

    def test_cert2asn_accepts_pem_der_and_asn1_input(self):
        _, leaf_cert = self._build_chain()

        pem_result = signer.cert2asn(leaf_cert.public_bytes(Encoding.PEM))
        der_result = signer.cert2asn(leaf_cert.public_bytes(Encoding.DER))
        passthrough = signer.cert2asn(der_result)

        self.assertEqual(pem_result.serial_number, leaf_cert.serial_number)
        self.assertEqual(der_result.serial_number, leaf_cert.serial_number)
        self.assertIs(passthrough, der_result)

    def test_extract_ocsp_url_from_cert_for_crypto_and_asn1_inputs(self):
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
        aia = x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("https://ocsp.example.test"),
                )
            ]
        )
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(aia, critical=False)
            .sign(issuer_key, hashes.SHA256())
        )

        self.assertEqual(
            signer.extract_ocsp_url_from_cert(leaf_cert),
            "https://ocsp.example.test",
        )

        leaf_asn1 = signer.cert2asn(leaf_cert.public_bytes(Encoding.DER))
        self.assertEqual(
            signer.extract_ocsp_url_from_cert(leaf_asn1),
            "https://ocsp.example.test",
        )

        no_aia_leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf No AIA")]))
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.UnrecognizedExtension(
                    ObjectIdentifier("1.2.3.4.5.6.7.8.9"),
                    b"\x05\x00",
                ),
                critical=False,
            )
            .sign(issuer_key, hashes.SHA256())
        )
        self.assertIsNone(signer.extract_ocsp_url_from_cert(no_aia_leaf))

    def test_sign_with_hsm_and_custom_attrs_callback(self):
        issuer_cert, leaf_cert = self._build_chain()
        cert_der = leaf_cert.public_bytes(Encoding.DER)

        class FakeHSM:
            def certificate(self):
                return b"key-id", cert_der

            def sign(self, keyid, tosign, hashalgo):
                self.last_call = (keyid, tosign, hashalgo)
                return b"hsm-signature"

        fake_hsm = FakeHSM()

        def custom_attrs(signed_value):
            return [
                signer.cms.CMSAttribute(
                    {
                        "type": signer.cms.CMSAttributeType("message_digest"),
                        "values": (signed_value,),
                    }
                )
            ]

        cms_bytes = signer.sign(
            b"payload",
            key=None,
            cert=leaf_cert,
            othercerts=[issuer_cert],
            hashalgo="sha256",
            attrs=custom_attrs,
            hsm=fake_hsm,
        )

        parsed = signer.cms.ContentInfo.load(cms_bytes)
        signature = parsed["content"]["signer_infos"][0]["signature"].native

        self.assertEqual(signature, b"hsm-signature")
        self.assertEqual(fake_hsm.last_call[0], b"key-id")
        self.assertEqual(fake_hsm.last_call[2], "sha256")

    def test_sign_pkcs1_includes_signed_attrs_and_uses_timestamp_hook(self):
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
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

        tsa = FakeTSA()
        with mock.patch("endesive.signer.fetch_ocsp_response", return_value=None) as ocsp_mock, \
             mock.patch("requests.post", side_effect=tsa.post), \
             mock.patch("endesive.signer.fetch_tsp_response", wraps=signer.fetch_tsp_response) as timestamp_mock:
                cms_bytes = signer.sign(
                    b"payload",
                    key=leaf_key,
                    cert=leaf_cert,
                    othercerts=[issuer_cert],
                    hashalgo="sha256",
                    attrs=True,
                    pss=False,
                    tspurl="https://tsa.example",
                    tspoptions={"verify": False, "username": "user", "password": "pass"},
                    ocspurl="https://ocsp.example",
                    ocspoptions={"issuer": issuer_cert},
                )

        parsed = signer.cms.ContentInfo.load(cms_bytes)
        sigalg = parsed["content"]["signer_infos"][0]["signature_algorithm"]["algorithm"].native
        attrs = parsed["content"]["signer_infos"][0]["signed_attrs"]

        self.assertEqual(sigalg, "rsassa_pkcs1v15")
        self.assertIsNotNone(attrs)
        ocsp_mock.assert_called_once()
        timestamp_mock.assert_called_once()
        unsigned_attrs = parsed["content"]["signer_infos"][0]["unsigned_attrs"]
        self.assertEqual(unsigned_attrs[0]["type"].native, "signature_time_stamp_token")

    def test_sign_pss_path_uses_rsassa_pss_algorithm(self):
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
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf")]))
            .issuer_name(issuer_name)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

        cms_bytes = signer.sign(
            b"payload",
            key=leaf_key,
            cert=leaf_cert,
            othercerts=[issuer_cert],
            hashalgo="sha256",
            attrs=True,
            pss=True,
        )

        parsed = signer.cms.ContentInfo.load(cms_bytes)
        sigalg = parsed["content"]["signer_infos"][0]["signature_algorithm"]["algorithm"].native

        self.assertEqual(sigalg, "rsassa_pss")


if __name__ == "__main__":
    unittest.main()
