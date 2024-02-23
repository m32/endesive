#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import datetime
import os

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import pdf

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


import test_cert

def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class PDFTests(unittest.TestCase):
    def test_pdf(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_pss(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'pss': True,
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms-pss.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_aligned(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'aligned': 0,
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms-aligned.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_encrypted(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'aligned': 0,
            'password': '1234',
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf-encrypted.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_signature_appearance(self):
        dct = {
            'aligned': 0,
            'sigflags': 3,
            'sigflagsft': 132,
            'sigpage': 0,
            'sigbutton': False,
            'sigfield': 'Signature-1667820612.078739',
            'auto_sigfield': False,
            'sigandcertify': False,
            'signaturebox': [175.79446979865773, 294.7236779911374, 447.47683221476507, 573.2810782865583],
            'contact': '',
            'location': '',
            'reason': '',
            'signingdate': "D:20221107123012+00'00'",
            'signature_appearance': {
                'background': [0.75, 0.8, 0.95],
                'outline': [0.2, 0.3, 0.5],
                'border': 1,
                'labels': True,
                'display': ['date']
            }
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-appearance.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_signature_appearance_ec(self):
        dct = {
            'aligned': 4096,
            'sigflags': 3,
            'sigflagsft': 132,
            'sigpage': 0,
            'sigbutton': False,
            'sigfield': 'Signature-1667820612.078739',
            'auto_sigfield': False,
            'sigandcertify': False,
            'signaturebox': [175.79446979865773, 294.7236779911374, 447.47683221476507, 573.2810782865583],
            'contact': '',
            'location': '',
            'reason': '',
            'signingdate': "D:20221107123012+00'00'",
            'signature_appearance': {
                'background': [0.75, 0.8, 0.95],
                'outline': [0.2, 0.3, 0.5],
                'border': 1,
                'labels': True,
                'display': ['date']
            }
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert3_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-appearance-ec.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_signature_manual(self):
        date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
        date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
        class User:
            full_name = 'u.full: ąćęłńóśżź'
            email = 'u.email: zażółcić gęślą jaźń'
            company = 'u.comp: ĄĆĘŁŃÓŚŻŹ'
            company_full_name = 'u.comp_full: ZAŻÓŁCIĆ GĘŚLĄ JAŹŃ'
        user = User()
        dct = {
            "aligned": 0,
            "sigflags": 3,
            "sigflagsft": 132,
            "sigpage": 0,
            "sigfield": "Signature1",
            "auto_sigfield": True,
            "signform": False,
            "signaturebox": (40, 110, 260, 190),
            "signature_manual": [
                ['text_box', f'Investor Name: {user.full_name}\nEmail: {user.email}\nDate: {date}\nLocation: Szczecin',
                    # font  *[bounding box], size, wrap, align, baseline, spacing
                    'default', 5, 10, 270, 40, 7, True, 'left', 'top'],
                ['fill_colour', 0.4, 0.4, 0.4],
                ['rect_fill', 0, 50, 250, 1],
                ['fill_colour', 0, 0, 0],
                ['text_box', user.company_full_name,
                    'DancingScript', 7, 25, 270, 50, 12, True, 'left', 'top', 1.2],
            ],
            "manual_fonts": {
            'DancingScript': '/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf'
            },
            "contact": user.email,
            "location": "Szczecin",
            "signingdate": date,
            "reason": f"Investment in {user.company} by {user.company_full_name}",
        }

        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-appearance.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

    def test_pdf_timestamp(self):
        tspurl = "http://public-qlts.certum.pl/qts-17"
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
        }
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256',
            None,
            tspurl,
        )
        fname = fname.replace('.pdf', '-signed-cms.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(test_cert.ca_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        results = pdf.verify(
            data, trusted_cert_pems, "/etc/ssl/certs"
        )
        for (hashok, signatureok, certok) in results:
            assert signatureok and hashok and certok

