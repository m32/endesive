# *-* coding: utf-8 *-*
import datetime
from cryptography import x509

from endesive import verifier

def verify(
    datas:bytes,
    datau:bytes,
    certs:list[x509.Certificate]=None
) -> tuple[bool, bool, bool, bool|None, list[datetime.datetime]|None, bool|None, datetime.datetime|None]:
    """
    Verifies signed bytes.

    Parameters:
        datas: Signed data as bytes.
        datau: Original data as bytes.
        certs: Optional list of system independent trusted certificates used to verify signature.

    Returns:
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
    return verifier.verify(datas, datau, certs)
