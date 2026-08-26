from __future__ import annotations

import os
from email.mime.application import MIMEApplication
from typing import TYPE_CHECKING

from asn1crypto import algos, cms, core
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers import modes as dmodes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as cmodes

from endesive import signer
from endesive.exceptions import EncryptionError


class EncryptedData(object):
    """S/MIME encrypted data container."""

    def _email(self, data: bytes, oaep: bool) -> str:
        """Wrap encrypted data in an S/MIME message body.

        Args:
            data: Encrypted payload bytes.
            oaep: Whether OAEP padding was used for key transport.

        Returns:
            The serialized S/MIME message as a string.
        """
        prefix = ["x-", ""][oaep]
        msg = MIMEApplication(data)
        del msg["Content-Type"]
        msg["Content-Disposition"] = 'attachment; filename="smime.p7m"'
        msg["Content-Type"] = (
            'application/%spkcs7-mime; smime-type=enveloped-data; name="smime.p7m"'
            % prefix
        )

        return msg.as_string()

    def _pad(self, s: bytes, block_size: int) -> bytes:
        """Pad the input using the PKCS#7 block-padding scheme.

        Args:
            s: Data to pad.
            block_size: Cipher block size in bytes.

        Returns:
            The padded payload.
        """
        n = block_size - len(s) % block_size
        if n == 0:
            n = block_size
            # return s
        n = bytes([n] * n)
        return s + n

    def _recipient_info(
        self, cert: x509.Certificate, session_key: bytes, oaep: bool
    ) -> cms.RecipientInfo:
        public_key = cert.public_key()
        tbs_cert = signer.cert2asn(cert)["tbs_certificate"]
        recipient_identifier = cms.RecipientIdentifier(
            name="issuer_and_serial_number",
            value={
                "issuer": tbs_cert["issuer"],
                "serial_number": tbs_cert["serial_number"],
            },
        )

        if oaep:
            encrypted_key = public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA512()),
                    algorithm=hashes.SHA512(),
                    label=None,
                ),
            )
            kea = cms.KeyEncryptionAlgorithm(
                {
                    "algorithm": cms.KeyEncryptionAlgorithmId("rsaes_oaep"),
                    "parameters": algos.RSAESOAEPParams(
                        {
                            "hash_algorithm": algos.DigestAlgorithm(
                                {"algorithm": "sha512"}
                            ),
                            "mask_gen_algorithm": algos.MaskGenAlgorithm(
                                {
                                    "algorithm": algos.MaskGenAlgorithmId("mgf1"),
                                    "parameters": {
                                        "algorithm": algos.DigestAlgorithmId("sha512"),
                                    },
                                }
                            ),
                            "p_source_algorithm": algos.PSourceAlgorithm(
                                {
                                    "algorithm": algos.PSourceAlgorithmId(
                                        "p_specified"
                                    ),
                                    "parameters": b"",
                                }
                            ),
                        }
                    ),
                }
            )
        else:
            kea = {"algorithm": "rsa"}
            encrypted_key = public_key.encrypt(session_key, padding.PKCS1v15())
        result = cms.RecipientInfo(
            name="ktri",
            value={
                "version": "v0",
                "rid": recipient_identifier,
                "key_encryption_algorithm": kea,
                "encrypted_key": core.OctetString(encrypted_key),
            },
        )
        return result

    def encrypt(
        self, data: bytes, certs: list[x509.Certificate], algo: str, oaep: bool
    ) -> str:
        """Encrypt payload bytes for all supplied recipient certificates.

        Args:
            data: Plain-text payload to encrypt.
            certs: List of recipient certificates.
            algo: Encryption algorithm name, for example ``aes256_cbc``.
            oaep: Whether to use OAEP padding for key transport.

        Returns:
            Serialized S/MIME enveloped-data message.
        """
        key_size = {
            "aes128": 16,
            "aes192": 24,
            "aes256": 32,
        }[algo.split("_", 1)[0]]
        block_size = 16
        session_key = os.urandom(key_size)
        iv = os.urandom(block_size)
        name = algo.split("_", 1)[1].upper()
        proc = getattr(dmodes, name, None)
        if not proc:
            proc = getattr(cmodes, name, None)
        if proc is None:
            raise EncryptionError(f"Invalid mode: {name}")
        cipher = Cipher(algorithms.AES(session_key), proc(iv), default_backend())

        data = self._pad(data, block_size)

        encryptor = cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()

        recipient_infos = []
        for cert in certs:
            recipient_info = self._recipient_info(cert, session_key, oaep)
            recipient_infos.append(recipient_info)

        enveloped_data = cms.ContentInfo(
            {
                "content_type": "enveloped_data",
                "content": {
                    "version": "v0",
                    "recipient_infos": recipient_infos,
                    "encrypted_content_info": {
                        "content_type": "data",
                        "content_encryption_algorithm": {
                            "algorithm": algo,
                            "parameters": iv,
                        },
                        "encrypted_content": data,
                    },
                },
            }
        )
        return self._email(enveloped_data.dump(), oaep)


def encrypt(
    data: bytes,
    certs: list[x509.Certificate],
    algo: str = "aes256_cbc",
    oaep: bool = False,
) -> str:
    """Encrypt data in the S/MIME enveloped-data format.

    Args:
        data: Plain-text payload to encrypt.
        certs: Recipient certificates.
        algo: Encryption algorithm name, for example ``aes256_cbc`` or ``aes256_ofb``.
        oaep: Whether to use OAEP padding for key encryption.

    Returns:
        Serialized S/MIME message data.

    Raises:
        EncryptionError: If the algorithm name is invalid.
    """
    if not (algo.startswith("aes") and algo.split("_", 1)[1] in ("cbc", "ofb")):
        raise EncryptionError(
            f"Invalid algorithm: {algo}. Expected aes*_cbc or aes*_ofb"
        )
    cls = EncryptedData()
    return cls.encrypt(data, certs, algo, oaep)
