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

from . import test_cert

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


class EMAILTests(unittest.TestCase):
    def test_email_signed_attr(self):
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')

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

        with open(test_cert.cert1_cert, 'rb') as fp:
            cert = fp.read()
        (hashok, signatureok, certok) = email.verify(datas.decode('utf8'), [cert,])
        assert hashok and signatureok and certok

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', test_cert.ca_cert,
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_pss(self):
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')

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

        with open(test_cert.cert1_cert, 'rb') as fp:
            cert = fp.read()
        (hashok, signatureok, certok) = email.verify(datas.decode('utf8'), [cert,])
        assert hashok and signatureok and certok

        cmd = [
            'openssl', 'cms', '-verify',
            '-signer', test_cert.cert1_cert,
            '-keyopt', 'rsa_padding_mode:pss', '-md', 'sha512',
            '-CAfile', test_cert.ca_cert,
            '-in', fname
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        # OpenSSL <= 1.1.1 outputs 'Verification successful'
        # OpenSSL >= 3.0.0 outputs 'CMS Verification successful'
        assert stderr == b'Verification successful\n' or stderr == b'CMS Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_custom(self):
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
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
            '-CAfile', test_cert.ca_cert,
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_noattr(self):
        p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
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
            '-CAfile', test_cert.ca_cert,
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_crypt(self):
        certs = (
            test_cert.CA().cert_load(test_cert.cert1_cert),
        )
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datae = email.encrypt(datau, certs, 'aes256_ofb')
        fname = fixture('smime-encrypted.txt')
        with open(fname, 'wt') as fh:
            fh.write(datae)

        key = test_cert.CA().key_load(test_cert.cert1_key, '1234')
        with io.open(fname, 'rt', encoding='utf-8') as fh:
            datae = fh.read()
        datad = email.decrypt(datae, key)

        assert datau == datad

    def _test_email_ssl_decrypt(self, algo, mode, oaep):
        certs = (
            test_cert.CA().cert_load(test_cert.cert1_cert),
        )

        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datae = email.encrypt(datau, certs, algo+'_'+mode, oaep)
        fname = fixture('smime-encrypted-{}-{}-{}.txt'.format(algo, mode, oaep))
        with open(fname, 'wt') as fh:
            fh.write(datae)

        if 0:
            key = test_cert.CA().key_load(test_cert.cert1_key, '1234')
            datau = email.decrypt(datae, key)

        if not oaep:
            cmd = [
                'openssl', 'smime', '-decrypt',
                '-recip', test_cert.cert1_cert,
                '-inkey', test_cert.cert1_key,
                '-passin', 'pass:1234',
                '-in', fname,
            ]
        else:
            cmd = [
                'openssl', 'cms', '-decrypt',
                '-recip', test_cert.cert1_cert,
                '-inkey', test_cert.cert1_key,
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
            test_cert.cert1_cert,
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b''
        assert stdout == b''

        key = test_cert.CA().key_load(test_cert.cert1_key, '1234')
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
            '-recip', test_cert.cert1_cert,
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

        key = test_cert.CA().key_load(test_cert.cert1_key, '1234')
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
