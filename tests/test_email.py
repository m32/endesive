#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os
import sys
import io
from subprocess import PIPE, Popen
from datetime import datetime

from OpenSSL import crypto
from endesive import email

import hashlib
from asn1crypto import cms, algos, core, pem, x509

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class EMAILTests(unittest.TestCase):
    def test_email_signed_attr(self):
        p12 = crypto.load_pkcs12(open(fixture('demo2_user1.p12'), 'rb').read(), '1234')
        datau = open(fixture('smime-unsigned.txt'), 'rb').read()
        datas = email.sign(datau,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256',
            attrs=True
        )
        fname = fixture('smime-signed-attr.txt')
        open(fname, 'wb').write(datas)

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_custom(self):
        p12 = crypto.load_pkcs12(open(fixture('demo2_user1.p12'), 'rb').read(), '1234')
        datau = open(fixture('smime-unsigned.txt'), 'rb').read()

        datau1 = datau.replace(b'\n', b'\r\n')
        hashalgo = 'sha256'
        signed_value = getattr(hashlib, hashalgo)(datau1).digest()
        attrs = [
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('1.2.840.113549.1.9.16.2.47'),
                'values': (algos.DigestAlgorithm({'algorithm': hashalgo}),),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': (signed_value,),
            }),
        ]

        datas = email.sign(datau,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256',
            attrs=attrs
        )
        fname = fixture('smime-signed-attr-custom.txt')
        open(fname, 'wb').write(datas)

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_noattr(self):
        p12 = crypto.load_pkcs12(open(fixture('demo2_user1.p12'), 'rb').read(), '1234')
        datau = open(fixture('smime-unsigned.txt'), 'rb').read()
        datas = email.sign(datau,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256',
            attrs=False
        )
        fname = fixture('smime-signed-noattr.txt')
        open(fname, 'wb').write(datas)

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_crypt(self):
        def load_cert(fname):
            with open(fname, 'rb') as f:
                cert_bytes = f.read()
                return crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)
        certs = (
            load_cert(fixture('demo2_user1.crt.pem')),
        )
        datau = open(fixture('smime-unsigned.txt'), 'rb').read()
        datae = email.encrypt(datau, certs, 'aes256_ofb')
        fname = fixture('smime-encrypted.txt')
        open(fname, 'wt').write(datae)

        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(fixture('demo2_user1.key.pem'), 'rb').read(), b'1234')
        key = key.to_cryptography_key()
        datae = io.open(fname, 'rt', encoding='utf-8').read()
        datad = email.decrypt(datae, key)

        assert datau == datad

    def test_email_ssl_decrypt(self):
        def load_cert(fname):
            with open(fname, 'rb') as f:
                cert_bytes = f.read()
                return crypto.load_certificate(crypto.FILETYPE_PEM, cert_bytes)
        certs = (
            load_cert(fixture('demo2_user1.crt.pem')),
        )
        datau = open(fixture('smime-unsigned.txt'), 'rb').read()
        datae = email.encrypt(datau, certs, 'aes256_ofb')
        fname = fixture('smime-encrypted.txt')
        open(fname, 'wt').write(datae)

        cmd = [
            'openssl', 'smime', '-decrypt',
            '-recip', fixture('demo2_user1.crt.pem'), '-inkey', fixture('demo2_user1.key.pem'),
            '-in', fname,
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b''
        lastbyte = stdout[-1]
        stdout = stdout[:len(stdout)-lastbyte]
        assert stdout == datau

    def test_email_ssl_encrypt(self):
        cmd = [
            'openssl', 'smime', '-encrypt', '-aes256',
            '-in', fixture('smime-unsigned.txt'),
            '-out', fixture('smime-ssl-encrypted.txt'),
            fixture('demo2_user1.crt.pem'),
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b''
        assert stdout == b''

        key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(fixture('demo2_user1.key.pem'), 'rb').read(), b'1234')
        key = key.to_cryptography_key()
        datae = io.open(fixture('smime-ssl-encrypted.txt'), 'rt', encoding='utf-8').read()
        datad = email.decrypt(datae, key)
        datau = open(fixture('smime-unsigned.txt'), 'rb').read()

        assert datau == datad.replace(b'\r\n', b'\n')
