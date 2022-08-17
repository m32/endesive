#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys
import datetime
import base64
import json
import hashlib
from asn1crypto import cms, core, util
from endesive import pdf


class Signer:
    def __init__(self, cert, sig, tosign):
        self.cert = cert
        self.sig = sig
        self.tosign = tosign
        self.mech = None

    def certificate(self):
        return 1, self.cert

    def sign(self, keyid, data, mech):
        if self.tosign:
            assert self.tosign == data
        self.tosign = data
        self.mech = mech
        if self.sig is None:
            sig = None
            if mech == "sha256":
                sig = b"\0" * 256
            return sig
        return self.sig


def main():
    def attrs(signed_value):
        result = [
            cms.CMSAttribute(
                {"type": cms.CMSAttributeType("content_type"), "values": ("data",)}
            ),
            cms.CMSAttribute(
                {
                    "type": cms.CMSAttributeType("message_digest"),
                    "values": (signed_value,),
                }
            ),
            cms.CMSAttribute(
                {
                    "type": cms.CMSAttributeType("signing_time"),
                    "values": (cms.Time({"utc_time": core.UTCTime(signed_time)}),),
                }
            ),
        ]
        return result

    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "mak@trisoft.com.pl",
        "location": "Szczecin",
        "reason": "Dokument podpisany cyfrowo",
        "signature": "Dokument podpisany cyfrowo",
        "signaturebox": (0, 0, 100, 100),
        "aligned": 16384,
        "attrs": attrs,
        "newid": "1",
    }

    pdfname = 'pdf.pdf'
    if len (sys.argv) > 1:
        pdfname = sys.argv[1]
    try:
        config = open(pdfname + ".json", "rt").read()
        config = json.loads(config)
    except FileNotFoundError:
        when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        config = {
            'when': when,
            'certificate': open("cert-hsm-user1.pem", "rt").read(),
            'signed_bytes': None,
            'tosign': None,
            'id': hashlib.md5(when.encode()).hexdigest()
        }
    dct['id'] = config['id'].encode()
    when = datetime.datetime.strptime(config['when'], "%Y-%m-%d %H:%M:%S")
    dct["signingdate"] = when.strftime("%Y%m%d%H%M%S+00'00'").encode()
    signed_time = datetime.datetime(
        when.year, when.month, when.day, when.hour, when.minute, when.second, 0, util.timezone.utc
    )
    cert = config['certificate'].encode('ascii')
    signed_bytes = config['signed_bytes']
    if signed_bytes is not None:
        signed_bytes = base64.decodebytes(signed_bytes.encode('ascii'))
    tosign = config['tosign']
    if tosign is not None:
        tosign = base64.decodebytes(tosign.encode('ascii'))

    clshsm = Signer(cert, signed_bytes, tosign)

    datau = open(pdfname, "rb").read()
    cls = pdf.cms.SignedData()
    datas = cls.sign(datau, dct, None, None, [], "sha256", clshsm, mode="sign")

    if signed_bytes is None:
        config['tosign'] = b"".join(base64.encodebytes(clshsm.tosign).split()).decode('ascii')
        json.dump(config, open(pdfname + ".json", "wt"), indent=4)
    else:
        fname = pdfname.replace(".pdf", "-signed-cms-hash.pdf")
        with open(fname, "wb") as fp:
            fp.write(datau)
            fp.write(datas)


main()
