# *-* coding: utf-8 *-*
import datetime
from email import message_from_string

from cryptography import x509

from endesive import verifier


def verify(
    message: str, certs: list[bytes | x509.Certificate] | None = None
) -> verifier.Result:
    """
    Verifiy S/MIME signed email.

    :param message: Email data as string.
    :param certs: Optional list of system independent trusted certificates used to verify signature.

    :return:
        hashok, signatureok, certok, ocspok, ocspdata, tspok, tspdata

        hashok: bool
            True if hash is matches, False otherwise.
        signatureok: bool
            True if signature is valid, False otherwise.
        certok: bool
            True if certificate is valid, False otherwise.
        ocspok: bool|None
            True if OCSP is valid, False if invalid, None if not present.
        ocspdata: list[datetime.datetime]|None
            List of OCSP produced_at and next_check_at datetimes,
            or None if not present.
        tspok: bool|None
            True if TSP is valid, False if invalid, None if not present.
        tspdata: datetime.datetime|None
            TSP produced_at datetime, or None if not present.
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
                raise ValueError("Multiple signatures")
            sig = part.get_payload(decode=True)
        elif ct == "application/pkcs7-signature":
            if sig is not None:
                raise ValueError("Multiple signatures")
            sig = part.get_payload(decode=True)
        elif ct == "text/plain":
            if plain is not None:
                raise ValueError("Multiple plain parts")
            plain = part.get_payload(decode=False)
    if sig is None:
        raise ValueError("not signed email")
    if plain is None:
        raise ValueError("part of signed email not found")

    plain = plain.encode("utf-8")
    plain = plain.replace(b"\n", b"\r\n")

    return verifier.verify(sig, plain, certs)
