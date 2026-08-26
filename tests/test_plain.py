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

if __name__ == '__main__':
    cls = PLAINTests()
    for n in dir(cls):
        if n.split('_')[0] == 'test':
            print(n)
            try:
                getattr(cls, n)()
            except Exception as exc:
                pass
