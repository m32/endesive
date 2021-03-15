#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms

# from endesive.pdf import cmsn as cms

# import logging
# logging.basicConfig(level=logging.DEBUG)


def main():
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "sigfield": "Signature1",
        "auto_sigfield": True,
        "password": "1234",
    }
    fname = "pdf_forms/blank_form.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    datas = cms.timestamp(
        datau,      # PDF data
        dct,        # config
        "sha256",   # hash
        'https://freetsa.org/tsr' # Timestamp server URL
        # { # Timestamp server credentials
        #     'username': 'user',
        #     'password': 'hunter2'
        #     }, 
        # {}, Timestamp server options 
        )
    fname = fname.replace(".pdf", "-timestamped-cms.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
