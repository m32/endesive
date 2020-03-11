#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os
from subprocess import PIPE, Popen
import sys
from datetime import datetime

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import plain

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class PLAINTests(unittest.TestCase):
    def test_plain_signed_attr(self):
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datas = plain.sign(datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=True
        )
        fname = fixture('plain-signed-attr.txt')
        with open(fname, 'wb') as fh:
            fh.write(datas)

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-content', fixture('plain-unsigned.txt'),
            '-in', fname, '-inform', 'der',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b'Verification successful\n'
        assert datau == stdout

    def test_plain_signed_noattr(self):
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datas = plain.sign(datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=False
        )
        fname = fixture('plain-signed-noattr.txt')
        with open(fname, 'wb') as fh:
            fh.write(datas)

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-content', fixture('plain-unsigned.txt'),
            '-in', fname, '-inform', 'der',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b'Verification successful\n'
        assert datau == stdout

    def test_plain_ssl_attr(self):
        cmd = [
            'openssl', 'smime', '-sign',
            '-md', 'sha256',
            '-binary',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fixture('plain-unsigned.txt'), '-out', fixture('plain-ssl-signed-attr.txt'), '-outform', 'der',
            '-inkey', fixture('demo2_user1.key.pem'),
            '-signer', fixture('demo2_user1.crt.pem'),
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert b'' == stdout
        assert b'' == stderr

        with open(fixture('demo2_ca.crt.pem'), 'rt') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        with open(fixture('plain-ssl-signed-attr.txt'), 'rb') as fh:
            datas = fh.read()
        (hashok, signatureok, certok) = plain.verify(datas, datau, trusted_cert_pems)
        assert signatureok and hashok and certok

    def test_plain_ssl_noattr(self):
        cmd = [
            'openssl', 'smime', '-sign',
            '-md', 'sha256',
            '-binary', '-noattr',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fixture('plain-unsigned.txt'), '-out', fixture('plain-ssl-signed-noattr.txt'), '-outform', 'der',
            '-inkey', fixture('demo2_user1.key.pem'),
            '-signer', fixture('demo2_user1.crt.pem'),
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert b'' == stdout
        assert b'' == stderr

        with open(fixture('demo2_ca.crt.pem'), 'rt') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        with open(fixture('plain-ssl-signed-noattr.txt'), 'rb') as fh:
            datas = fh.read()
        (hashok, signatureok, certok) = plain.verify(datas, datau, trusted_cert_pems)
        assert signatureok and hashok and certok
