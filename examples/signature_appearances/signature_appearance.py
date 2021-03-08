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
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        "auto_sigfield": True,
        #"sigandcertify": False,
        "signaturebox": (72, 396, 360, 468),
        "signform": False,
        "sigfield": "Signature",

        # Text will be in the default font
        # Fields in the list display will be included in the text listing
        # Icon and background can both be set to images by having their
        #   value be a path to a file or a PIL Image object
        # If background is a list it is considered to be an opaque RGB colour
        # Outline is the colour used to draw both the border and the text
        "signature_appearance": {
            'background': [0.75, 0.8, 0.95],
            'icon': '../signature_test.png',
            'outline': [0.2, 0.3, 0.5],
            'border': 2,
            'labels': True,
            'display': 'CN,DN,date,contact,reason,location'.split(','),
            },

        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }
    with open("../demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )
    fname = "../pdf_forms/blank_form.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    fname = fname.replace(".pdf", "-signature_appearance.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
