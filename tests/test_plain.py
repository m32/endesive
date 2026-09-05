import unittest
from subprocess import PIPE, Popen

from test_cert import (
    CA,
    ca_root_cert,
    ca_sub_cert,
    cert1_cert,
    cert1_key,
    cert1_p12,
    fixture,
)

from endesive import plain
from endesive.exceptions import HashAlgorithmError


class PLAINTests(unittest.TestCase):
    def test_plain_signed_attr(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
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
            '-CAfile', ca_root_cert,
            '-content', fixture('plain-unsigned.txt'),
            '-in', fname,
            '-inform', 'der',
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert stderr == b'Verification successful\n'
        assert datau == stdout

    def test_plain_signed_noattr(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
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
            '-CAfile', ca_root_cert,
            '-content', fixture('plain-unsigned.txt'),
            '-in', fname,
            '-inform', 'der',
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
            '-certfile', ca_sub_cert,
            '-in', fixture('plain-unsigned.txt'),
            '-out', fixture('plain-ssl-signed-attr.txt'),
            '-outform', 'der',
            '-inkey', cert1_key,
            '-passin', 'pass:1234',
            '-signer', cert1_cert,
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert b'' == stdout
        assert b'' == stderr

        trusted_cert_pems = []
        with open(ca_root_cert, 'rb') as fp:
            trusted_cert_pems.append(fp.read())
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        with open(fixture('plain-ssl-signed-attr.txt'), 'rb') as fh:
            datas = fh.read()
        result = plain.verify(datas, datau, trusted_cert_pems)

        assert result.signatureok and result.hashok and result.certok

    def test_plain_ssl_noattr(self):
        cmd = [
            'openssl', 'smime', '-sign',
            '-md', 'sha256',
            '-binary', '-noattr',
            '-certfile', ca_sub_cert,
            '-in', fixture('plain-unsigned.txt'),
            '-out', fixture('plain-ssl-signed-noattr.txt'),
            '-outform', 'der',
            '-inkey', cert1_key,
            '-passin', 'pass:1234',
            '-signer', cert1_cert,
        ]
        process = Popen(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()
        assert b'' == stdout
        assert b'' == stderr

        trusted_cert_pems = []
        with open(ca_root_cert, 'rb') as fp:
            trusted_cert_pems.append(fp.read())
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        with open(fixture('plain-ssl-signed-noattr.txt'), 'rb') as fh:
            datas = fh.read()
        result = plain.verify(datas, datau, trusted_cert_pems)

        assert result.signatureok and result.hashok and result.certok

    def test_plain_sign_pss_and_verify(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datas = plain.sign(
            datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=True,
            pss=True,
        )

        trusted_cert_pems = []
        with open(ca_root_cert, 'rb') as fp:
            trusted_cert_pems.append(fp.read())

        result = plain.verify(datas, datau, trusted_cert_pems)
        assert result.signatureok and result.hashok and result.certok

    def test_plain_verify_detects_tampered_payload(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datas = plain.sign(
            datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=True,
        )
        tampered = datau + b'\nTAMPERED'

        trusted_cert_pems = []
        with open(ca_root_cert, 'rb') as fp:
            trusted_cert_pems.append(fp.read())

        result = plain.verify(datas, tampered, trusted_cert_pems)
        assert result.signatureok and not result.hashok and result.certok

    def test_plain_verify_accepts_trusted_cert_as_pem_and_der_bytes(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        datas = plain.sign(
            datau,
            p12[0], p12[1], p12[2],
            'sha256',
            attrs=True,
        )

        # trusted roots accepted as DER bytes
        with open(ca_root_cert, 'rb') as fp:
            trusted_pem = fp.read()
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        trusted_der = x509.load_pem_x509_certificate(trusted_pem).public_bytes(
            serialization.Encoding.DER
        )
        result_der = plain.verify(datas, datau, [trusted_der])
        assert result_der.signatureok and result_der.hashok and result_der.certok

        result_pem = plain.verify(datas, datau, [trusted_pem])
        assert result_pem.signatureok and result_pem.hashok and result_pem.certok

    def test_plain_verify_rejects_trusted_cert_object_input(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()
        datas = plain.sign(datau, p12[0], p12[1], p12[2], 'sha256', attrs=True)

        from cryptography import x509
        with open(ca_root_cert, 'rb') as fp:
            trusted_obj = x509.load_pem_x509_certificate(fp.read())

        with self.assertRaises(TypeError):
            plain.verify(datas, datau, [trusted_obj])

    def test_plain_sign_rejects_unsupported_hash_algorithm(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('plain-unsigned.txt'), 'rb') as fh:
            datau = fh.read()

        with self.assertRaises(HashAlgorithmError):
            plain.sign(
                datau,
                p12[0], p12[1], p12[2],
                'sha999',
                attrs=True,
            )

if __name__ == '__main__':
    cls = PLAINTests()
    for n in dir(cls):
        if n.split('_')[0] == 'test':
            print(n)
            try:
                getattr(cls, n)()
            except Exception as exc:
                pass
