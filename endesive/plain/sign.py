# *-* coding: utf-8 *-*
from endesive import signer


def sign(datau, key, cert, certs, hashalgo='sha1', attrs=True, pss=False):
    return signer.sign(datau, key, cert, certs, hashalgo, attrs, pss=pss)
