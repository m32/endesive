from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from endesive import signer
from endesive.exceptions import HashAlgorithmError

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


# micalg parameter values (RFC 5751 section 3.4.3.2); SHA-1 keeps the
# "sha1" spelling of RFC 3851, which OpenSSL also writes
MICALG = {
    "sha1": b"sha1",
    "sha224": b"sha-224",
    "sha256": b"sha-256",
    "sha384": b"sha-384",
    "sha512": b"sha-512",
}


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
            HashAlgorithmError: If hash algorithm is unsupported
        """
        # checked before signing, which may ask for an HSM PIN
        bhashalgo = MICALG.get(hashalgo.lower())
        if bhashalgo is None:
            raise HashAlgorithmError(f"Unsupported hash algorithm: {hashalgo}")
        # canonical CRLF line endings, also for input already using them
        datau = datau.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        datas = signer.sign(datau, key, cert, othercerts, hashalgo, attrs, pss=pss)
        datas = base64.encodebytes(datas)
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
