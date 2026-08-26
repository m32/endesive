import datetime
import sys

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.pdf import cms

# import logging
# logging.basicConfig(level=logging.DEBUG)


def main():
    date = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=12)
    date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "aligned": 0,
        "sigflags": 3,
        "sigflagsft": 132,
        "sigpage": 0,
        # "auto_sigfield": False,
        # "sigandcertify": False,
        # "signaturebox": (0, 0, 590, 155),
        "signform": True,
        "sigfield": "Signature",
        #             Text will be in the default font
        "signature": "Signed field!",
        # default configuration for the text appearance
        "text": {
            "wraptext": True,
            "fontsize": 12,
            "textalign": "left",
            "linespacing": 1.2,
        },
        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "signingdate": date,
        "reason": "Dokument podpisany cyfrowo aą cć eę lł nń oó sś zż zź",
        "password": "1234",
    }
    with open("ca/demo2_user1.p12", "rb") as fp:
        p12 = pkcs12.load_key_and_certificates(
            fp.read(), b"1234", backends.default_backend()
        )
    fname = "blank_form.pdf"
    if len(sys.argv) > 1:
        fname = sys.argv[1]
    datau = open(fname, "rb").read()
    datas = cms.sign(datau, dct, p12[0], p12[1], p12[2], "sha256")
    with open("generated/pdf-sign-cms-form-signature.pdf", "wb") as fp:
        fp.write(datau)
        fp.write(datas)


main()
