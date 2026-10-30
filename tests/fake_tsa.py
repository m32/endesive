"""In-process RFC 3161 time-stamping authority used to test TSP handling."""

from __future__ import annotations

import datetime
import hashlib
from types import SimpleNamespace

from asn1crypto import cms, tsp, x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class FakeTSA:
    """Answers time-stamp requests with tokens signed by its own CA.

    Patch ``requests.post`` with :meth:`post` and trust :attr:`root_pem`.

    Args:
        status: PKI status put into every response.
        tamper_imprint: Answer with an imprint which does not match the request.
    """

    def __init__(self, status: str = "granted", tamper_imprint: bool = False):
        self.status = status
        self.tamper_imprint = tamper_imprint
        self.requests: list[tsp.TimeStampReq] = []

        now = datetime.datetime.now(datetime.UTC)
        validity = (now - datetime.timedelta(days=1), now + datetime.timedelta(days=30))

        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.root_cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Fake TSA Root"))
            .issuer_name(_name("Fake TSA Root"))
            .public_key(root_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(validity[0])
            .not_valid_after(validity[1])
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )

        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(_name("Fake TSA"))
            .issuer_name(self.root_cert.subject)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(validity[0])
            .not_valid_after(validity[1])
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                critical=False,
            )
            .sign(root_key, hashes.SHA256())
        )
        self.root_pem = self.root_cert.public_bytes(serialization.Encoding.PEM)

    def respond(self, request: bytes) -> bytes:
        req = tsp.TimeStampReq.load(request)
        self.requests.append(req)
        if self.status not in ("granted", "granted_with_mods"):
            return tsp.TimeStampResp({"status": {"status": self.status}}).dump()

        imprint = req["message_imprint"]
        if self.tamper_imprint:
            hashed = bytearray(imprint["hashed_message"].native)
            hashed[0] ^= 0xFF
            imprint = tsp.MessageImprint(
                {"hash_algorithm": imprint["hash_algorithm"], "hashed_message": bytes(hashed)}
            )
        tst_info = tsp.TSTInfo(
            {
                "version": "v1",
                "policy": "1.2.3.4",
                "message_imprint": imprint,
                "serial_number": len(self.requests),
                "gen_time": datetime.datetime.now(datetime.UTC),
                "nonce": req["nonce"],
            }
        )

        cert = asn1_x509.Certificate.load(self.cert.public_bytes(serialization.Encoding.DER))
        signer_info = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                            {"issuer": cert.issuer, "serial_number": cert.serial_number}
                        )
                    }
                ),
                "digest_algorithm": {"algorithm": "sha256"},
                "signed_attrs": [
                    {"type": "content_type", "values": ["tst_info"]},
                    {
                        "type": "message_digest",
                        "values": [hashlib.sha256(tst_info.dump()).digest()],
                    },
                    {
                        "type": "signing_certificate_v2",
                        "values": [
                            {
                                "certs": [
                                    {
                                        "hash_algorithm": {"algorithm": "sha256"},
                                        "cert_hash": hashlib.sha256(cert.dump()).digest(),
                                    }
                                ]
                            }
                        ],
                    },
                ],
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": b"",
            }
        )
        tosign = b"\x31" + signer_info["signed_attrs"].dump()[1:]
        signer_info["signature"] = self.key.sign(tosign, padding.PKCS1v15(), hashes.SHA256())

        token = cms.ContentInfo(
            {
                "content_type": "signed_data",
                "content": {
                    "version": "v3",
                    "digest_algorithms": [{"algorithm": "sha256"}],
                    "encap_content_info": {"content_type": "tst_info", "content": tst_info},
                    "certificates": [cert],
                    "signer_infos": [signer_info],
                },
            }
        )
        return tsp.TimeStampResp(
            {"status": {"status": self.status}, "time_stamp_token": token}
        ).dump()

    def post(self, url, data=None, headers=None, **kwargs):
        return SimpleNamespace(
            status_code=200,
            headers={"Content-Type": "application/timestamp-reply"},
            content=self.respond(data),
        )
