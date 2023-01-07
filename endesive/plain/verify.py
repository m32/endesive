# *-* coding: utf-8 *-*
from endesive import verifier


def verify(datas, datau, certs=None, systemCertsPath=None):
    return verifier.verify(datas, datau, certs, systemCertsPath=None)
