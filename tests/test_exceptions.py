import importlib

import pytest

from endesive.exceptions import (
    DecryptionError,
    EmailVerificationError,
    EncryptionError,
    EndesiveError,
    HashAlgorithmError,
    HSMError,
    SignerError,
    TimestampError,
)
from endesive.hsm import SSHAgentHSM
from endesive.signer import Signer

email_sign = importlib.import_module("endesive.email.sign")
email_encrypt = importlib.import_module("endesive.email.encrypt")
email_decrypt = importlib.import_module("endesive.email.decrypt")
email_verify = importlib.import_module("endesive.email.verify")


def test_custom_exceptions_are_specific_and_inheritable():
    assert issubclass(EndesiveError, ValueError)
    assert issubclass(DecryptionError, EndesiveError)
    assert issubclass(EmailVerificationError, EndesiveError)
    assert issubclass(HashAlgorithmError, EndesiveError)
    assert issubclass(SignerError, EndesiveError)
    assert issubclass(TimestampError, EndesiveError)
    assert issubclass(EncryptionError, EndesiveError)
    assert issubclass(HSMError, EndesiveError)

    with pytest.raises(DecryptionError):
        raise DecryptionError("bad crypt")


def test_signer_rejects_invalid_attrs_type():
    with pytest.raises(SignerError, match="attrs must be bool or callable"):
        Signer(b"data", cert=None, othercerts=[], hashalgo="sha256", attrs="yes")  # type: ignore[arg-type]


def test_email_sign_rejects_unsupported_hash_algorithm():
    p12 = (
        importlib.import_module("tests.test_cert")
        .CA()
        .pk12_load(importlib.import_module("tests.test_cert").cert1_p12, "1234")
    )
    with pytest.raises(HashAlgorithmError, match="Unsupported hash algorithm"):
        email_sign.sign(
            b"payload",
            p12[0],
            p12[1],
            p12[2],
            "sha999",
            attrs=True,
        )


def test_email_encrypt_rejects_invalid_algorithm_name():
    with pytest.raises(EncryptionError, match="Invalid algorithm"):
        email_encrypt.encrypt(b"payload", [], algo="md5_cbc")


@pytest.mark.parametrize(
    "message",
    [
        "Content-Transfer-Encoding: uuencode\r\nContent-Type: application/x-pkcs7-mime\r\n\r\n",
        "Content-Transfer-Encoding: base64\r\nContent-Type: text/plain\r\n\r\n",
        "Content-Transfer-Encoding: base64\r\nContent-Type: application/x-pkcs7-mime\r\n\r\n",
    ],
)
def test_email_decrypt_rejects_invalid_message_shapes(message):
    with pytest.raises(DecryptionError):
        email_decrypt.decrypt(message, key=None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "message",
    [
        "From: x@example.com\r\n\r\n",
        "Content-Type: multipart/mixed\r\n\r\n",
    ],
)
def test_email_verify_rejects_missing_signature(message):
    with pytest.raises(EmailVerificationError):
        email_verify.verify(message)


def test_hsm_decode_fp_rejects_unsupported_algorithm():
    with pytest.raises(HSMError, match="Unsupported fingerprint algorithm"):
        SSHAgentHSM._decode_fp("SHA3:abcd")
