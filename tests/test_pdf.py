#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import pdf

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


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
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
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

        with open(fixture('demo2_ca.crt.pem'), 'rt') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        (hashok, signatureok, certok) = pdf.verify(data, trusted_cert_pems)
        assert signatureok and hashok and certok
