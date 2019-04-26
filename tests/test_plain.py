#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os
from subprocess import PIPE, Popen
import sys
from datetime import datetime

from OpenSSL.crypto import load_pkcs12
from endesive import plain

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class PLAINTests(unittest.TestCase):
    def test_plain_signed_attr(self):
        p12 = load_pkcs12(open(fixture('demo2_user1.p12'), 'rb').read(), '1234')
        datau = open(fixture('plain-unsigned.txt'), 'rb').read()
        datas = plain.sign(datau,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256',
            attrs=True
        )
        fname = fixture('plain-signed-attr.txt')
        open(fname, 'wb').write(datas)

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
        p12 = load_pkcs12(open(fixture('demo2_user1.p12'), 'rb').read(), '1234')
        datau = open(fixture('plain-unsigned.txt'), 'rb').read()
        datas = plain.sign(datau,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256',
            attrs=False
        )
        fname = fixture('plain-signed-noattr.txt')
        open(fname, 'wb').write(datas)

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

        trusted_cert_pems = (open(fixture('demo2_ca.crt.pem'), 'rt').read(),)
        datau = open(fixture('plain-unsigned.txt'), 'rb').read()
        datas = open(fixture('plain-ssl-signed-attr.txt'), 'rb').read()
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

        trusted_cert_pems = (open(fixture('demo2_ca.crt.pem'), 'rt').read(),)
        datau = open(fixture('plain-unsigned.txt'), 'rb').read()
        datas = open(fixture('plain-ssl-signed-noattr.txt'), 'rb').read()
        (hashok, signatureok, certok) = plain.verify(datas, datau, trusted_cert_pems)
        assert signatureok and hashok and certok
