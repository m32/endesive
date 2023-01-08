#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os
import sys
import io
from subprocess import PIPE, Popen
from datetime import datetime

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key
from endesive import email

import hashlib
from asn1crypto import cms, algos, core, pem

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class EMAILTests(unittest.TestCase):
    def test_email_signed_attr(self):
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datas = email.sign(datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=True
        )
        fname = fixture('smime-signed-attr.txt')
        with open(fname, 'wb') as fh:
            fh.write(datas)

        with open(fixture('demo2_user1.crt.pem'), 'rb') as f:
            cert = f.read()
        (hashok, signatureok, certok) = email.verify(datas.decode('utf8'), [cert,])
        assert hashok and signatureok and certok

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_pss(self):
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datas = email.sign(datau,
            p12[0], p12[1], p12[2],
            'sha512',
            attrs=True,
            pss=True
        )
        fname = fixture('smime-signed-attr-pss.txt')
        with open(fname, 'wb') as fh:
            fh.write(datas)

        with open(fixture('demo2_user1.crt.pem'), 'rb') as f:
            cert = f.read()
        (hashok, signatureok, certok) = email.verify(datas.decode('utf8'), [cert,])
        assert hashok and signatureok and certok

        cmd = [
            'openssl', 'cms', '-verify',
            '-signer', fixture('demo2_user1.crt.pem'),
            '-keyopt', 'rsa_padding_mode:pss', '-md', 'sha512',
            '-CAfile', fixture('demo2_ca.crt.pem'),
            '-in', fname
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_custom(self):
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datau1 = datau.replace(b'\n', b'\r\n')
        hashalgo = 'sha256'
        signed_value = getattr(hashlib, hashalgo)(datau1).digest()
        attrs = [
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('content_type'),
                'values': ('data',),
            }),
            cms.CMSAttribute({
                'type': cms.CMSAttributeType('message_digest'),
                'values': (signed_value,),
            }),
        ]

        datas = email.sign(datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=attrs
        )
        fname = fixture('smime-signed-attr-custom.txt')
        with open(fname, 'wb') as fh:
            fh.write(datas)

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
        with open(fixture('demo2_user1.p12'), 'rb') as fp:
            p12 = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datas = email.sign(datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=False
        )
        fname = fixture('smime-signed-noattr.txt')
        with open(fname, 'wb') as fh:
            fh.write(datas)

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
        def load_cert(relative_path):
            with open(relative_path, 'rb') as f:
                return x509.load_pem_x509_certificate(f.read(), backends.default_backend())
        certs = (
            load_cert(fixture('demo2_user1.crt.pem')),
        )
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datae = email.encrypt(datau, certs, 'aes256_ofb')
        fname = fixture('smime-encrypted.txt')
        with open(fname, 'wt') as fh:
            fh.write(datae)

        with open(fixture('demo2_user1.key.pem'), 'rb') as fh:
            key = load_pem_private_key(fh.read(), b'1234', backends.default_backend())
        with io.open(fname, 'rt', encoding='utf-8') as fh:
            datae = fh.read()
        datad = email.decrypt(datae, key)

        assert datau == datad

    def _test_email_ssl_decrypt(self, algo, mode, oaep):
        def load_cert(relative_path):
            with open(relative_path, 'rb') as f:
                return x509.load_pem_x509_certificate(f.read(), backends.default_backend())
        certs = (
            load_cert(fixture('demo2_user1.crt.pem')),
        )

        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datae = email.encrypt(datau, certs, algo+'_'+mode, oaep)
        fname = fixture('smime-encrypted-{}-{}-{}.txt'.format(algo, mode, oaep))
        with open(fname, 'wt') as fh:
            fh.write(datae)

        if 0:
            with open(fixture('demo2_user1.key.pem'), 'rb') as fh:
                key = load_pem_private_key(fh.read(), b'1234', backends.default_backend())
            datau = email.decrypt(datae, key)

        if not oaep:
            cmd = [
                'openssl', 'smime', '-decrypt',
                '-recip', fixture('demo2_user1.crt.pem'),
                '-inkey', fixture('demo2_user1.key.pem'),
                '-passin', 'pass:1234',
                '-in', fname,
            ]
        else:
            cmd = [
                'openssl', 'cms', '-decrypt',
                '-recip', fixture('demo2_user1.crt.pem'),
                '-inkey', fixture('demo2_user1.key.pem'),
                '-passin', 'pass:1234',
                '-in', fname,
            ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b''
        if stdout != datau:
            lastbyte = stdout[-1]
            stdout = stdout[:len(stdout)-lastbyte]
        assert stdout == datau

    def test_email_ssl_decrypt_aes128_cbc_False(self):
        self._test_email_ssl_decrypt('aes128', 'cbc', False)

    def test_email_ssl_decrypt_aes192_cbc_False(self):
        self._test_email_ssl_decrypt('aes192', 'cbc', False)

    def test_email_ssl_decrypt_aes256_cbc_False(self):
        self._test_email_ssl_decrypt('aes256', 'cbc', False)

    def test_email_ssl_decrypt_aes128_ofb_False(self):
        self._test_email_ssl_decrypt('aes128', 'ofb', False)

    def test_email_ssl_decrypt_aes192_ofb_False(self):
        self._test_email_ssl_decrypt('aes192', 'ofb', False)

    def test_email_ssl_decrypt_aes256_ofb_False(self):
        self._test_email_ssl_decrypt('aes256', 'ofb', False)

    def test_email_ssl_decrypt_aes128_cbc_True(self):
        self._test_email_ssl_decrypt('aes128', 'cbc', True)

    def test_email_ssl_decrypt_aes192_cbc_True(self):
        self._test_email_ssl_decrypt('aes192', 'cbc', True)

    def test_email_ssl_decrypt_aes256_cbc_True(self):
        self._test_email_ssl_decrypt('aes256', 'cbc', True)

    def test_email_ssl_decrypt_aes128_ofb_True(self):
        self._test_email_ssl_decrypt('aes128', 'ofb', True)

    def test_email_ssl_decrypt_aes192_ofb_True(self):
        self._test_email_ssl_decrypt('aes192', 'ofb', True)

    def test_email_ssl_decrypt_aes256_ofb_True(self):
        self._test_email_ssl_decrypt('aes256', 'ofb', True)

    def _test_email_ssl_encrypt_smime(self, algo):
        fname = fixture('smime-ssl-encrypted-smime-{}.txt'.format(algo))
        cmd = [
            'openssl', 'smime', '-encrypt', '-'+algo,
            '-in', fixture('smime-unsigned.txt'),
            '-out', fname,
            fixture('demo2_user1.crt.pem'),
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b''
        assert stdout == b''

        with open(fixture('demo2_user1.key.pem'), 'rb') as fh:
            key = load_pem_private_key(fh.read(), b'1234', backends.default_backend())
        with io.open(fname, 'rt', encoding='utf-8') as fh:
            datae = fh.read()
        datad = email.decrypt(datae, key)
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        assert datau == datad.replace(b'\r\n', b'\n')

    def test_email_ssl_encrypt_aes256(self):
        self._test_email_ssl_encrypt_smime('aes256')

    def _test_email_ssl_encrypt_cms(self, mode):
        fname = fixture('smime-ssl-encrypted-cms-{}.txt'.format(mode))
        cmd = [
            'openssl', 'cms', '-encrypt',
            '-recip', fixture('demo2_user1.crt.pem'),
            '-in', fixture('smime-unsigned.txt'),
            '-out', fname,
            '-md', 'sha512'
        ]
        if mode is not None:
            cmd.extend([
                '-keyopt', 'rsa_padding_mode:{}'.format(mode),
            ])
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b''
        assert stdout == b''

        with open(fixture('demo2_user1.key.pem'), 'rb') as fh:
            key = load_pem_private_key(fh.read(), b'1234', backends.default_backend())
        with io.open(fname, 'rt', encoding='utf-8') as fh:
            datae = fh.read()
        datad = email.decrypt(datae, key)
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        assert datau == datad.replace(b'\r\n', b'\n')

    def test_email_ssl_encrypt_cms_oaep(self):
        self._test_email_ssl_encrypt_cms('oaep')

    def test_email_ssl_encrypt_cms(self):
        self._test_email_ssl_encrypt_cms(None)
