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
        "signature_manual": [
            #                R     G     B
            ['fill_colour', 0.95, 0.95, 0.95],

            #            *[bounding box]
            ['rect_fill', 0, 0, 270, 18],

            #                  R    G    B
            ['stroke_colour', 0.8, 0.8, 0.8],

            #          key  *[bounding box]
            ['image', 'sig0', 0, 0, 59, 15],

            #        inset
            ['border', 2],

            #         font     fs 
            ['font', 'default', 7],
            #               R  G  B
            ['fill_colour', 0, 0, 0],

            #            text
            ['text_box', 'signed using endesive\ndate: {}'.format(date),
                # font  *[bounding box], fs, wrap, align, baseline
                'default', 0, 2, 270, 18, 7, True, 'right', 'top'],
            ],
        #   key: name used in image directives
        # value: PIL Image object or path to image file
        "manual_images": {'sig0': '../signature_test.png'},
        #   key: name used in font directives
        # value: path to TTF Font file
        "manual_fonts": {},

        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }
    with open("demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )
    fname = "../pdf_forms/blank_form.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    fname = fname.replace(".pdf", "-signed-cms.pdf")
    with open(fname, "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
