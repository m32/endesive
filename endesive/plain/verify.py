from __future__ import annotations

from typing import TYPE_CHECKING

from endesive import verifier

if TYPE_CHECKING:
    from cryptography import x509


def verify(
    datas: bytes, datau: bytes, certs: list[bytes | x509.Certificate] | None = None
) -> verifier.Result:
    """
    Verifies signed bytes.

    Parameters:
        datas: Signed data as bytes.
        datau: Original data as bytes.
        certs: Optional list of system independent trusted certificates used to verify signature.

    Returns:
        Result object containing the verification status and related data.

    """
    return verifier.verify(datas, datau, certs)
