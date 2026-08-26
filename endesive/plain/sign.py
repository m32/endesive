from __future__ import annotations

from typing import TYPE_CHECKING

from endesive import signer

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


def sign(
    datau: bytes,
    key: PrivateKeyTypes,
    cert: x509.Certificate,
    certs: list[x509.Certificate],
    hashalgo: str = "sha256",
    attrs: bool = True,
    pss: bool = False,
) -> bytes:
    """
    Sign data with private key without any encapsulation.

    Parameters:
        datau: Data to sign (bytes).
        key: Private key to sign with (PrivateKeyTypes).
        cert: Certificate to sign with (x509.Certificate).
        certs: List of additional certificates (list of x509.Certificate).
        hashalgo: Hash algorithm to use (str, default 'sha256').
        attrs: Whether to include attributes (bool, default True).
        pss: Whether to use PSS padding (bool, default False).

    Returns:
        Signed data as bytes.
    """
    return signer.sign(datau, key, cert, certs, hashalgo, attrs, pss=pss)
