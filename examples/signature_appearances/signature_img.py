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
        #"auto_sigfield": False,
        #"sigandcertify": False,
        #"signaturebox": (0, 0, 590, 155),
        "signform": True,
        "sigfield": "Signature",
        #                PIL Image object or path to image file
        #                Image will be resized to fit bounding box
        "signature_img": '../signature_test.png',
        "signature_img_distort": False, # default True
        "signature_img_centred": False, # default True

        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }
    with open("../ca/demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )
    fname = "../pdf_forms/blank_form.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    fname = fname.replace(".pdf", "-signature_img.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
