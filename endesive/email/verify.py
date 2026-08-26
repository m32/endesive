from __future__ import annotations

from email import message_from_string
from typing import TYPE_CHECKING

from endesive import verifier
from endesive.exceptions import EmailVerificationError

if TYPE_CHECKING:
    from cryptography import x509


def verify(
    message: str, certs: list[bytes | x509.Certificate] | None = None
) -> verifier.Result:
    """Verify the signature of an S/MIME email message.

    Args:
        message: Email content as a string.
        certs: Optional trusted certificates used to validate the signer chain.

    Returns:
        A verification result object containing hash, signature, certificate,
        OCSP, and TSP status information.
    """
    msg = message_from_string(message)
    sig = None
    plain = None
    for part in msg.walk():
        ct = part.get_content_type()
        # multipart/* are just containers
        if ct.split("/")[0] == "multipart":
            continue
        if ct == "application/x-pkcs7-signature":
            if sig is not None:
                raise EmailVerificationError("Multiple signatures")
            sig = part.get_payload(decode=True)
        elif ct == "application/pkcs7-signature":
            if sig is not None:
                raise EmailVerificationError("Multiple signatures")
            sig = part.get_payload(decode=True)
        elif ct == "text/plain":
            if plain is not None:
                raise EmailVerificationError("Multiple plain parts")
            plain = part.get_payload(decode=False)
    if sig is None:
        raise EmailVerificationError("not signed email")
    if plain is None:
        raise EmailVerificationError("part of signed email not found")

    plain = plain.encode("utf-8")
    plain = plain.replace(b"\n", b"\r\n")

    return verifier.verify(sig, plain, certs)
