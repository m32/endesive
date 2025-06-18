# *-* coding: utf-8 *-*
from cryptography import x509

from endesive import verifier

def verify(datas:bytes, datau:bytes, certs:list[x509.Certificate]=None) -> tuple[bool, bool, bool]:
    """
    Verifies signed bytes.
    :param datas: Signed data as bytes.
    :param datau: Original data as bytes.
    :param certs: List of additional certificates used to verify signature (system independent).
    :return: A tuple containing three boolean values:
        - True if the hash matches.
        - True if the signature is valid.
        - True if the certificate used for signing is trusted and valid.
    """
    return verifier.verify(datas, datau, certs)
