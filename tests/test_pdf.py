#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os

from OpenSSL.crypto import load_pkcs12
from endesive import pdf

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class PDFTests(unittest.TestCase):
    def test_pdf(self):
        dct = {
            b'sigflags': 3,
            b'contact': b'mak@trisoft.com.pl',
            b'location': b'Szczecin',
            b'signingdate': b'20180731082642+02\'00\'',
            b'reason': b'Dokument podpisany cyfrowo',
        }
        p12 = load_pkcs12(open(fixture('demo2_user1.p12'), 'rb').read(), '1234')
        fname = fixture('pdf.pdf')
        datau = open(fname, 'rb').read()
        datas = pdf.cms.sign(datau, dct,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        trusted_cert_pems = (open(fixture('demo2_ca.crt.pem'), 'rt').read(),)
        data = open(fname, 'rb').read()
        (hashok, signatureok, certok) = pdf.verify(data, trusted_cert_pems)
        assert signatureok and hashok and certok
