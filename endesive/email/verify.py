# *-* coding: utf-8 *-*
from email import message_from_string

from cryptography import x509

from endesive import verifier


def verify(data:bytes, certs:list[x509.Certificate]=None) -> tuple[bool, bool, bool]:
    """
    Verifiy S/MIME signed email.

    :param data: Email data as bytes.
    :param certs: List of additional certificates used to verify signature (system independent).
    :return:
        hashok, signatureok, certok

        hashok: bool
            True if the hash matches.
        signatureok: bool
            True if the signature is valid.
        certok: bool
            True if the certificate used for signing is trusted and valid.
    """
    msg = message_from_string(data)
    sig = None
    plain = None
    for part in msg.walk():
        ct = part.get_content_type()
        # multipart/* are just containers
        if ct.split('/')[0] == 'multipart':
            continue
        if ct == 'application/x-pkcs7-signature':
            sig = part.get_payload(decode=True)
        elif ct == 'application/pkcs7-signature':
            sig = part.get_payload(decode=True)
        elif ct == 'text/plain':
            plain = part.get_payload(decode=False)
    if sig is None:
        raise ValueError('not signed email')

    plain = plain.encode('utf-8')
    plain = plain.replace(b'\n', b'\r\n')

    return verifier.verify(sig, plain, certs)
