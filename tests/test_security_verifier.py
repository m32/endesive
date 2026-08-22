#!/usr/bin/env vpython3
# coding: utf-8
import datetime
import hashlib
import unittest
from types import SimpleNamespace
from unittest import mock

from asn1crypto import ocsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from endesive import verifier as generic_verifier
from endesive.pdf.verify import PDFVerifier, verify as pdf_verify


class SecurityVerifierTests(unittest.TestCase):
    class _Native:
        def __init__(self, value):
            self.native = value

    class _FakePdfCert:
        def __init__(self, serial):
            self.native = {"tbs_certificate": {"serial_number": serial}}
            self.chosen = SimpleNamespace(dump=lambda: b"DER")

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

    def test_generic_verifier_raises_on_duplicate_signer_certificate(self):
        serial = 123456
        signed_data = {
            "signer_infos": [
                {
                    "signature": self._Native(b"sig"),
                    "sid": self._Native({"serial_number": serial}),
                    "signed_attrs": None,
                }
            ],
            "digest_algorithms": [{"algorithm": self._Native("sha256")}],
            "certificates": [
                self._FakePdfCert(serial),
                self._FakePdfCert(serial),
            ],
        }

        verify_data = object.__new__(generic_verifier.SignatureVerifier)
        verify_data.verifier = mock.Mock()

        with mock.patch("endesive.verifier.cms.ContentInfo.load", return_value={"content": signed_data}):
            with mock.patch("endesive.verifier.cx509.load_pem_x509_certificate", return_value=mock.Mock()):
                with self.assertRaises(ValueError):
                    verify_data.verify_data(b"cms", b"payload")

    def test_generic_verifier_raises_when_signer_certificate_missing(self):
        serial = 123456
        signed_data = {
            "signer_infos": [
                {
                    "signature": self._Native(b"sig"),
                    "sid": self._Native({"serial_number": serial}),
                    "signed_attrs": None,
                }
            ],
            "digest_algorithms": [{"algorithm": self._Native("sha256")}],
            "certificates": [
                self._FakePdfCert(serial + 1),
            ],
        }

        verify_data = object.__new__(generic_verifier.SignatureVerifier)
        verify_data.verifier = mock.Mock()

        with mock.patch("endesive.verifier.cms.ContentInfo.load", return_value={"content": signed_data}):
            with mock.patch("endesive.verifier.cx509.load_pem_x509_certificate", return_value=mock.Mock()):
                with self.assertRaises(ValueError):
                    verify_data.verify_data(b"cms", b"payload")


if __name__ == "__main__":
    unittest.main()
