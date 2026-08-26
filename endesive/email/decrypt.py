from __future__ import annotations

from email import message_from_string
from typing import TYPE_CHECKING

from asn1crypto import cms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers import modes as dmodes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as cmodes

from endesive.exceptions import DecryptionError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes


class DecryptedData(object):
    """S/MIME encrypted data decryption handler."""

    def decrypt(self, message: str, key: PrivateKeyTypes) -> bytes:
        """Decrypt an S/MIME payload using the supplied private key.

        Args:
            message: Encrypted S/MIME message as a string.
            key: Private key used for decryption.

        Returns:
            Decrypted plaintext as bytes.

        Raises:
            DecryptionError: If the payload is malformed or decryption fails.
        """
        msg = message_from_string(message)
        if msg.get("Content-Transfer-Encoding") != "base64":
            raise DecryptionError("Unknown Content-Transfer-Encoding")
        if msg.get_content_type() not in (
            "application/x-pkcs7-mime",
            "application/pkcs7-mime",
        ):
            raise DecryptionError(f"Unknown Content-Type: {msg.get_content_type()}")
        data = None
        for part in msg.walk():
            # multipart/* are just containers
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type() not in (
                "application/x-pkcs7-mime",
                "application/pkcs7-mime",
            ):
                continue
            if data is not None:
                raise DecryptionError("Multiple encrypted parts found in the message")
            data = part.get_payload(decode=True)
        if data is None:
            raise DecryptionError("No encrypted part found in the message")

        try:
            signed_data = cms.ContentInfo.load(data)["content"]
        except (ValueError, TypeError) as exc:
            raise DecryptionError("Invalid PKCS#7 encrypted payload") from exc
        # signed_data.debug()

        algo = signed_data["encrypted_content_info"]["content_encryption_algorithm"][
            "algorithm"
        ].native
        param = signed_data["encrypted_content_info"]["content_encryption_algorithm"][
            "parameters"
        ].native
        edata = signed_data["encrypted_content_info"]["encrypted_content"].native
        pkey = signed_data["recipient_infos"].native[0]["encrypted_key"]

        keyalgo = signed_data["recipient_infos"].native[0]["key_encryption_algorithm"]
        if keyalgo["algorithm"] == "rsaes_oaep":
            keyparam = keyalgo["parameters"]
            mga = keyparam["mask_gen_algorithm"]
            mgh = getattr(hashes, mga["parameters"]["algorithm"].upper())()
            pad = padding.OAEP(
                mgf=getattr(padding, mga["algorithm"].upper())(algorithm=mgh),
                algorithm=getattr(
                    hashes, keyparam["hash_algorithm"]["algorithm"].upper()
                )(),
                label=keyparam["p_source_algorithm"]["parameters"],
            )
            udata = key.decrypt(pkey, pad)  # pyright: ignore[reportAttributeAccessIssue]
        elif keyalgo["algorithm"] == "rsaes_pkcs1v15":
            udata = key.decrypt(pkey, padding.PKCS1v15())  # pyright: ignore[reportAttributeAccessIssue]
        else:
            raise DecryptionError(f"Unknown key algorithm: {keyalgo['algorithm']}")

        algorithm, mode = algo.split("_", 1)
        algorithm = algorithm.upper()
        proc = getattr(dmodes, mode.upper(), None)
        if not proc:
            proc = getattr(cmodes, mode.upper())
        if algorithm in (
            "AES128",
            "AES192",
            "AES256",
        ):
            cipher = Cipher(algorithms.AES(udata), proc(param), default_backend())
        elif algorithm == "TRIPLEDES":
            raise DecryptionError(f"Unknown algorithm: {algo}")
            # XXX will be removed in version 48.0.0
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

            # XXX howto decode parameters to CBC mode ?
            mode = "cbc"
            cipher = Cipher(TripleDES(udata), proc(param), default_backend())
        else:
            raise DecryptionError(f"Unknown algorithm: {algo}")

        decryptor = cipher.decryptor()
        udata = decryptor.update(edata) + decryptor.finalize()
        # if keyalgo['algorithm'] != 'rsaes_oaep':
        nb = udata[-1]
        # BUG 2322/2327: 1<=nb<=blocksize
        if nb < 1 or nb > 16:
            raise DecryptionError(f"Unknown block size: {nb}")
        if udata[-nb:] != bytes([nb] * nb):
            raise DecryptionError(f"Unknown padding: {nb}")
        udata = udata[:-nb]
        return udata


def decrypt(data: str, key: PrivateKeyTypes) -> bytes:
    """Decrypt the supplied S/MIME payload using the provided private key.

    Args:
        data: Encrypted message content as a string.
        key: Private key used for decryption.

    Returns:
        The decrypted plaintext as bytes.
    """
    cls = DecryptedData()
    return cls.decrypt(data, key)
