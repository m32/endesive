# *-* coding: utf-8 *-*
from cryptography import x509

from endesive import verifier

def verify(datas:bytes, datau:bytes, certs:list[x509.Certificate]=None) -> tuple[bool, bool, bool]:
    """
    Verifies signed bytes.

    Parameters:
        datas: Signed data as bytes.
        datau: Original data as bytes.
        certs: List of additional certificates used to verify signature (system independent).

    Returns:
        hashok, signatureok, certok
        
        hashok : bool
            True if the hash matches.
        signatureok : bool
            True if the signature is valid.
        certok : bool
            True if the certificate used for signing is trusted and valid.
    """
    return verifier.verify(datas, datau, certs)
