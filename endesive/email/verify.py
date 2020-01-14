# *-* coding: utf-8 *-*
from email import message_from_string

from endesive import verifier


def verify(data, certs=None):
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

    plain = plain.encode('utf-8').replace(b'\n', b'\r\n')

    return verifier.verify(sig, plain, certs)
