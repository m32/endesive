import datetime
import inspect
import unittest
from types import SimpleNamespace
from unittest import mock

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    NameOID,
    ObjectIdentifier,
)

from endesive import email, plain, signer
from endesive.pdf import cms as pdf_cms


class SecuritySignerTests(unittest.TestCase):
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

    def test_fetch_ocsp_response_sets_timeout_and_handles_request_error(self):
        issuer_cert, leaf_cert = self._build_chain()

        with mock.patch(
            "endesive.signer.requests.post",
            side_effect=requests.exceptions.Timeout("timeout"),
        ) as post_mock:
            result = signer.fetch_ocsp_response(leaf_cert, issuer_cert, "https://ocsp.example")

        self.assertIsNone(result)
        self.assertEqual(post_mock.call_args.kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)

    def test_fetch_ocsp_response_returns_none_on_http_error(self):
        issuer_cert, leaf_cert = self._build_chain()
        fake_response = SimpleNamespace(status_code=503, content=b"")

        with mock.patch("endesive.signer.requests.post", return_value=fake_response) as post_mock:
            result = signer.fetch_ocsp_response(leaf_cert, issuer_cert, "https://ocsp.example")

        self.assertIsNone(result)
        self.assertEqual(post_mock.call_args.kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)

    def test_timestamp_adds_default_timeout_and_uses_random_nonce(self):
        fake_response = SimpleNamespace(headers={}, content=b"")

        with mock.patch("endesive.signer.secrets.randbits", return_value=42) as randbits_mock:
            with mock.patch("endesive.signer.requests.post", return_value=fake_response) as post_mock:
                with self.assertRaises(ValueError):
                    signer.timestamp(
                        None,
                        "sha256",
                        "https://tsa.example",
                        credentials=None,
                        req_options={},
                        prehashed=b"\x00" * 32,
                    )

        randbits_mock.assert_called_once_with(64)
        self.assertEqual(post_mock.call_args.kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)

    def test_cert2asn_accepts_pem_der_and_asn1_input(self):
        _, leaf_cert = self._build_chain()

        pem_result = signer.cert2asn(leaf_cert.public_bytes(Encoding.PEM), cert_bytes=False)
        der_result = signer.cert2asn(leaf_cert.public_bytes(Encoding.DER), cert_bytes=False)
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

        leaf_asn1 = signer.cert2asn(leaf_cert.public_bytes(Encoding.DER), cert_bytes=False)
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

    def test_timestamp_uses_basic_auth_when_credentials_present(self):
        fake_response = SimpleNamespace(
            headers={"Content-Type": "text/plain"},
            content=b"",
        )

        with mock.patch("endesive.signer.requests.post", return_value=fake_response) as post_mock:
            with self.assertRaises(ValueError):
                signer.timestamp(
                    b"payload",
                    "sha256",
                    "https://tsa.example",
                    credentials={"username": "user", "password": "pass"},
                    req_options={"verify": False},
                )

        headers = post_mock.call_args.kwargs["headers"]
        self.assertEqual(headers["Authorization"], "Basic dXNlcjpwYXNz")
        self.assertEqual(post_mock.call_args.kwargs["verify"], False)
        self.assertEqual(post_mock.call_args.kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)

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

        with mock.patch("endesive.signer.fetch_ocsp_response", return_value=None) as ocsp_mock:
            with mock.patch("endesive.signer.timestamp", return_value=[]) as timestamp_mock:
                cms_bytes = signer.sign(
                    b"payload",
                    key=leaf_key,
                    cert=leaf_cert,
                    othercerts=[issuer_cert],
                    hashalgo="sha256",
                    attrs=True,
                    pss=False,
                    timestampurl="https://tsa.example",
                    timestampcredentials={"username": "user", "password": "pass"},
                    timestamp_req_options={"verify": False},
                    ocspurl="https://ocsp.example",
                    ocspissuer=issuer_cert,
                )

        parsed = signer.cms.ContentInfo.load(cms_bytes)
        sigalg = parsed["content"]["signer_infos"][0]["signature_algorithm"]["algorithm"].native
        attrs = parsed["content"]["signer_infos"][0]["signed_attrs"]

        self.assertEqual(sigalg, "rsassa_pkcs1v15")
        self.assertIsNotNone(attrs)
        ocsp_mock.assert_called_once()
        timestamp_mock.assert_called_once()

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
