#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os
import sys
import io
import base64
from subprocess import PIPE, Popen
from datetime import datetime
from email import message_from_string

from cryptography import x509
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12, load_pem_private_key
from endesive import email

import hashlib
from asn1crypto import cms, algos, core, pem

from test_cert import (
    fixture, CA, HSM,
    ca_root_cert,
    ca_sub_cert,
    cert1_key, cert1_cert, cert1_p12,
    cert2_key, cert2_cert, cert2_p12,
    cert3_key, cert3_cert, cert3_p12,
)

class EMAILTests(unittest.TestCase):
    def _encrypt_for_cert(self, cert_path=cert1_cert, algo='aes256_ofb', oaep=False):
        certs = (CA().cert_load(cert_path),)
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datae = email.encrypt(datau, certs, algo, oaep)
        return datau, datae

    def _tamper_smime_cms(self, datae, mutator):
        msg = message_from_string(datae)
        cms_der = msg.get_payload(decode=True)
        cms_info = cms.ContentInfo.load(cms_der)
        mutator(cms_info)
        msg.set_payload(base64.encodebytes(cms_info.dump()).decode('ascii'))
        return msg.as_string()

    def _tamper_padding_value(self, datae, original_pad, target_pad):
        def mutator(cms_info):
            encrypted_data = cms_info['content']
            encrypted_content_info = encrypted_data['encrypted_content_info']
            encrypted_content = bytearray(encrypted_content_info['encrypted_content'].native)
            encrypted_content[-1] ^= (original_pad ^ target_pad)
            encrypted_content_info['encrypted_content'] = bytes(encrypted_content)

        return self._tamper_smime_cms(datae, mutator)

    def _tamper_inconsistent_padding(self, datae, original_pad, target_last_pad, target_prev_byte):
        def mutator(cms_info):
            encrypted_data = cms_info['content']
            encrypted_content_info = encrypted_data['encrypted_content_info']
            encrypted_content = bytearray(encrypted_content_info['encrypted_content'].native)
            encrypted_content[-1] ^= (original_pad ^ target_last_pad)
            encrypted_content[-2] ^= (original_pad ^ target_prev_byte)
            encrypted_content_info['encrypted_content'] = bytes(encrypted_content)

        return self._tamper_smime_cms(datae, mutator)

    def test_email_signed_attr(self):
        p12 = CA().pk12_load(cert1_p12, '1234')

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

        with io.open(fname, 'rt', encoding='utf-8') as fp:
            datas = fp.read()
        with open(ca_sub_cert, 'rb') as fp:
            cert = fp.read()
        result = email.verify(datas, [cert,])

        assert result.hashok and result.signatureok and result.certok

        cmd = [
            'openssl', 'smime', '-verify',
            '-CAfile', ca_root_cert,
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_pss(self):
        p12 = CA().pk12_load(cert1_p12, '1234')

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

        with io.open(fname, 'rt', encoding='utf-8') as fp:
            datas = fp.read()
        with open(ca_sub_cert, 'rb') as fp:
            cert = fp.read()
        result = email.verify(datas, [cert,])

        assert result.hashok and result.signatureok and result.certok

        cmd = [
            'openssl', 'cms', '-verify',
            '-signer', cert1_cert,
            '-keyopt', 'rsa_padding_mode:pss', '-md', 'sha512',
            '-CAfile', ca_root_cert,
            '-in', fname
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        # OpenSSL <= 1.1.1 outputs 'Verification successful'
        # OpenSSL >= 3.0.0 outputs 'CMS Verification successful'
        assert stderr == b'Verification successful\n' or stderr == b'CMS Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_attr_custom(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datau1 = datau.replace(b'\n', b'\r\n')
        hashalgo = 'sha256'
        signed_value = getattr(hashlib, hashalgo)(datau1).digest()
        def attrs(_):
            return [
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
            '-CAfile', ca_root_cert,
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_signed_noattr(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
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
            '-CAfile', ca_root_cert,
            '-in', fname, '-inform', 'SMIME',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        assert stderr == b'Verification successful\n'
        assert datau.replace(b'\n', b'\r\n') == stdout

    def test_email_crypt(self):
        certs = (
            CA().cert_load(cert1_cert),
        )
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datae = email.encrypt(datau, certs, 'aes256_ofb')
        fname = fixture('smime-encrypted.txt')
        with open(fname, 'wt') as fh:
            fh.write(datae)

        key = CA().key_load(cert1_key, '1234')
        with io.open(fname, 'rt', encoding='utf-8') as fh:
            datae = fh.read()
        datad = email.decrypt(datae, key)

        assert datau == datad

    def test_email_decrypt_rejects_non_base64_encoding(self):
        key = CA().key_load(cert1_key, '1234')
        msg = (
            'Content-Type: application/pkcs7-mime\n'
            'Content-Transfer-Encoding: 7bit\n\n'
            'Zm9v\n'
        )
        with self.assertRaises(Exception):
            email.decrypt(msg, key)

    def test_email_decrypt_rejects_invalid_content_type(self):
        key = CA().key_load(cert1_key, '1234')
        msg = (
            'Content-Type: text/plain\n'
            'Content-Transfer-Encoding: base64\n\n'
            'Zm9v\n'
        )
        with self.assertRaises(Exception):
            email.decrypt(msg, key)

    def test_email_decrypt_rejects_wrong_private_key(self):
        datau, datae = self._encrypt_for_cert(cert1_cert)
        wrong_key = CA().key_load(cert2_key, '1234')
        try:
            decrypted = email.decrypt(datae, wrong_key)
        except Exception:
            return
        assert decrypted != datau

    def test_email_decrypt_rejects_invalid_cms_payload(self):
        key = CA().key_load(cert1_key, '1234')
        msg = (
            'Content-Type: application/pkcs7-mime\n'
            'Content-Transfer-Encoding: base64\n\n'
            'Zm9v\n'
        )
        with self.assertRaises(Exception):
            email.decrypt(msg, key)

    def test_email_decrypt_tampered_ciphertext_does_not_match_plaintext(self):
        datau, datae = self._encrypt_for_cert(cert1_cert)

        def mutator(cms_info):
            encrypted_data = cms_info['content']
            encrypted_content_info = encrypted_data['encrypted_content_info']
            encrypted_content = bytearray(encrypted_content_info['encrypted_content'].native)
            encrypted_content[len(encrypted_content) // 2] ^= 0x01
            encrypted_content_info['encrypted_content'] = bytes(encrypted_content)

        tampered = self._tamper_smime_cms(datae, mutator)
        key = CA().key_load(cert1_key, '1234')

        try:
            decrypted = email.decrypt(tampered, key)
        except Exception:
            return

        assert decrypted != datau

    def test_email_decrypt_tampered_algorithm_is_rejected(self):
        certs = (
            CA().cert_load(cert1_cert),
        )
        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datae = email.encrypt(datau, certs, 'aes256_ofb')

        def mutator(cms_info):
            encrypted_data = cms_info['content']
            encrypted_content_info = encrypted_data['encrypted_content_info']
            encrypted_content_info['content_encryption_algorithm']['algorithm'] = cms.EncryptionAlgorithmId('des')

        tampered = self._tamper_smime_cms(datae, mutator)
        key = CA().key_load(cert1_key, '1234')
        with self.assertRaises(Exception):
            email.decrypt(tampered, key)

    def test_email_decrypt_invalid_padding_zero_byte(self):
        datau, datae = self._encrypt_for_cert(cert1_cert, algo='aes256_ofb')
        original_pad = 16 - (len(datau) % 16)
        tampered = self._tamper_padding_value(datae, original_pad, 0)

        key = CA().key_load(cert1_key, '1234')
        try:
            decrypted = email.decrypt(tampered, key)
        except ValueError:
            pass

    def test_email_decrypt_invalid_padding_too_large(self):
        datau, datae = self._encrypt_for_cert(cert1_cert, algo='aes256_ofb')
        original_pad = 16 - (len(datau) % 16)
        tampered = self._tamper_padding_value(datae, original_pad, 17)

        key = CA().key_load(cert1_key, '1234')
        try:
            decrypted = email.decrypt(tampered, key)
        except ValueError:
            pass

    def test_email_decrypt_invalid_padding_inconsistent_bytes(self):
        datau, datae = self._encrypt_for_cert(cert1_cert, algo='aes256_ofb')
        original_pad = 16 - (len(datau) % 16)
        tampered = self._tamper_inconsistent_padding(
            datae,
            original_pad,
            target_last_pad=2,
            target_prev_byte=1,
        )

        key = CA().key_load(cert1_key, '1234')
        try:
            decrypted = email.decrypt(tampered, key)
        except ValueError:
            pass

    def _test_email_ssl_decrypt(self, algo, mode, oaep):
        certs = (
            CA().cert_load(cert1_cert),
        )

        with open(fixture('smime-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datae = email.encrypt(datau, certs, algo+'_'+mode, oaep)
        fname = fixture('smime-encrypted-{}-{}-{}.txt'.format(algo, mode, oaep))
        with open(fname, 'wt') as fh:
            fh.write(datae)

        if 0:
            key = CA().key_load(cert1_key, '1234')
            datau = email.decrypt(datae, key)

        if not oaep:
            cmd = [
                'openssl', 'smime', '-decrypt',
                '-recip', cert1_cert,
                '-inkey', cert1_key,
                '-passin', 'pass:1234',
                '-in', fname,
            ]
        else:
            cmd = [
                'openssl', 'cms', '-decrypt',
                '-recip', cert1_cert,
                '-inkey', cert1_key,
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
            cert1_cert,
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b''
        assert stdout == b''

        key = CA().key_load(cert1_key, '1234')
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
            '-recip', cert1_cert,
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

        key = CA().key_load(cert1_key, '1234')
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
