from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from endesive import signer
from endesive.exceptions import HashAlgorithmError

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


class SignedData(object):
    """S/MIME signed data container."""

    def _email(
        self, hashalgo: bytes, datau: bytes, datas: bytes, prefix: bytes
    ) -> bytes:
        """Format signed data as S/MIME message."""
        s = b"""\
MIME-Version: 1.0
Content-Type: multipart/signed; protocol="application/%spkcs7-signature"; micalg="%s"; boundary="----46F1AAD10BE922477643C0A33C40D389"

This is an S/MIME signed message

------46F1AAD10BE922477643C0A33C40D389
%s
------46F1AAD10BE922477643C0A33C40D389
Content-Type: application/%spkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"

%s
------46F1AAD10BE922477643C0A33C40D389--

""" % (prefix, hashalgo, datau, prefix, datas)
        return s

    def sign(
        self,
        datau: bytes,
        key: PrivateKeyTypes,
        cert: x509.Certificate,
        othercerts: list[x509.Certificate],
        hashalgo: str,
        attrs: bool,
        pss: bool = False,
    ) -> bytes:
        """Sign data with private key and encapsulate as S/MIME.

        Args:
            datau: Data to sign
            key: Private key
            cert: Certificate
            othercerts: Additional certificates
            hashalgo: Hash algorithm name
            attrs: Include attributes
            pss: Use PSS padding

        Returns:
            Signed S/MIME data as bytes

        Raises:
            ValueError: If hash algorithm is unsupported
        """
        datau = datau.replace(b"\n", b"\r\n")
        datas = signer.sign(datau, key, cert, othercerts, hashalgo, attrs, pss=pss)
        datas = base64.encodebytes(datas)
        if hashalgo == "sha1":
            bhashalgo = b"sha1"
        elif hashalgo == "sha256":
            bhashalgo = b"sha-256"
        elif hashalgo == "sha512":
            bhashalgo = b"sha-512"
        else:
            raise HashAlgorithmError(f"Unsupported hash algorithm: {hashalgo}")
        prefix = [b"x-", b""][pss]
        data = self._email(bhashalgo, datau, datas, prefix)
        return data


def sign(
    datau: bytes,
    key: PrivateKeyTypes,
    cert: x509.Certificate,
    certs: list[x509.Certificate],
    hashalgo: str = "sha256",
    attrs: bool = True,
    pss: bool = False,
) -> bytes:
    """Sign data and wrap the result as an S/MIME message.

    Args:
        datau: Data to sign as bytes.
        key: Private key used for signing.
        cert: Signing certificate.
        certs: Additional certificates to include with the signature.
        hashalgo: Hash algorithm name, such as ``sha256``.
        attrs: Whether signed attributes should be included.
        pss: Whether PSS padding should be used.

    Returns:
        Signed S/MIME data as bytes.

    Raises:
        HashAlgorithmError: If the requested hash algorithm is unsupported.
    """
    cls = SignedData()
    return cls.sign(datau, key, cert, certs, hashalgo, attrs, pss)
