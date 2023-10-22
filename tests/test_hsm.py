#!/usr/bin/env vpython3
# coding: utf-8
import unittest
import os
import stat
import subprocess
import sysconfig
import datetime
import base64
import email

from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

from asn1crypto import pem as asn1pem
from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive import hsm, signer, verifier
import PyKCS11 as PK11

import test_cert

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

def fixture(fname):
    return os.path.join(fixtures_dir, fname)

dllpath = os.path.join(sysconfig.get_config_var('LIBDIR'), 'softhsm/libsofthsm2.so')

os.makedirs(os.path.join(fixtures_dir, 'softhsm2'), exist_ok=True)
os.environ['SOFTHSM2_CONF'] = fixture('softhsm2.conf')
open(fixture('softhsm2.conf'), 'wt').write('''\
log.level = DEBUG
directories.tokendir = %s/softhsm2/
objectstore.backend = file
slots.removable = false
''' % fixtures_dir)

class HSM(hsm.HSM):
    def main(self):
        cakeyID = bytes((0x1,))
        rec = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, cakeyID)])
        if len(rec) == 0:
            label = 'hsm CA'
            self.gen_privkey(label, cakeyID)
            self.ca_gen(label, cakeyID, 'hsm CA')

        keyID = bytes((0x66,0x66,0x90))
        rec = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, keyID)])
        if len(rec) == 0:
            label = 'hsm USER 1'
            self.gen_privkey(label, keyID)
            self.ca_sign(keyID, label, 0x666690, "hsm USER 1", 365, cakeyID)

        self.cert_export(fixture('cert-hsm-ca'), cakeyID)
        self.cert_export(fixture('cert-hsm-user1'), keyID)

def compose(From, To, Subject, Body, Attachment, signer):
    # create message object instance
    msg = MIMEMultipart(_subtype="signed", micalg="SHA1", protocol="application/pkcs7-signature")

    # setup the parameters of the message
    msg['From'] = From
    msg['To'] = To
    msg['Subject'] = Subject
    msg['Date'] = email.utils.format_datetime(datetime.datetime.now())
    msg.preamble = "This is a multipart message in MIME format."

    env = MIMEMultipart(_subtype='mixed')
    body = MIMEText(Body.decode())
    #del body['MIME-Version']
    env.attach(body)

    with open(Attachment, 'rb') as fp:
        app = MIMEApplication(fp.read(), _subtype="txt")
    app.add_header('content-disposition', 'attachment', filename=Attachment)
    env.attach(app)

    msg.attach(env)

    sig = MIMEBase(_maintype='application', _subtype='pkcs7-signature', name="smime.p7s")
    sig.add_header('Content-Disposition', 'attachment', filename='smime.p7s')
    sig.add_header('Content-Transfer-Encoding', 'base64')
    datau = env.as_string().encode()
    #open(fixture('test_ssh_sign-sign.txt'),'wb').write(datau)
    sig.set_payload(signer(datau))
    #del sig['MIME-Version']
    msg.attach(sig)

    return msg, env, sig


def sign(datau, key, cert, othercerts, hashalgo, hsm):
    datau = datau.replace(b'\n', b'\r\n')
    datas = signer.sign(datau, key, cert, othercerts, hashalgo, attrs=True, pss=False, hsm=hsm)
    return base64.encodebytes(datas)


class HSMTests(unittest.TestCase):
    def test_base(self):
        cls = hsm.BaseHSM()
        try:
            cls.certificate()
        except NotImplementedError:
            pass
        try:
            cls.sign(None, None, None)
        except NotImplementedError:
            pass

    def test_create(self):
        cls = HSM(dllpath)
        cls.create("endesieve", "secret1", "secret2")
        cls.login("endesieve", "secret1")
        try:
            cls.main()
        finally:
            cls.logout()

    def test_load(self):
        cls = HSM(dllpath)
        cls.login("endesieve", "secret1")
        cakeyID = bytes((0x1,))
        cls.cert_load(cakeyID)
        keyID = bytes((0x66,0x66,0x90))
        cls.cert_load(keyID)
        cls.logout()

    def test_ssh_sign(self):
        key, cert, othercerts = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')

        agent = hsm.SSHAgentHSM(cert)

        # lookup the ssh fingerprint for the certificates public key
        keyid, _ = agent.certificate()
        keyfile = None
        try:
            # is the public key known to the ssh-agent yet?
            agent.key(keyid)
        except ValueError:
            agent.close()

            # we have to add the key to the ssh-agent
            # remove the key password, dump in traditional openssl so ssh-agent can add the key
            keyfile = fixture('demo2_user1.key.nopass.pem')
            with open(keyfile, 'wb') as fp:
                # dump the key
                fp.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(keyfile, 0o600)
            # pub file so ssh-add -d can be used
            pubfile = fixture('demo2_user1.key.nopass.pem.pub')
            with open(pubfile, 'wb') as fp:
                # convert the public key of the certificate to ssh public key format
                fp.write(cert.public_key().public_bytes(
                    encoding=serialization.Encoding.OpenSSH,
                    format=serialization.PublicFormat.OpenSSH
                ))

            subprocess.call(["ssh-add", keyfile])

            # reconnect the agent so the key is visible to paramiko
            agent = hsm.SSHAgentHSM(cert)

        with open(fixture('smime-unsigned.txt'), 'rb') as fp:
            datau = fp.read()

        msg, env, sig = compose(
            From='root+from@localhost',
            To='root+to@localhost',
            Subject='this is the subject',
            Body=datau,
            Attachment=fixture('smime-unsigned.txt'),
            signer=lambda data: sign(data, None, cert, othercerts, 'sha256', agent)
        )
        datas = msg.as_bytes(unixfrom=True)
        with open(fixture('smime-signed-hsm-ssh.txt'), 'wb') as fp:
            fp.write(datas)

        # we added, so we remove the key from ssh-agent
        keyfile = fixture('demo2_user1.key.nopass.pem')
        if keyfile:
            subprocess.call(['ssh-add', '-d', keyfile])

        agent.close()

    def test_ssh_verify(self):
        with open(test_cert.cert1_cert, 'rb') as fp:
            cert = fp.read()
        with open(fixture('smime-signed-hsm-ssh.txt'), 'rt') as fp:
            datas = fp.read()

        msg = email.message_from_string(datas)
        sig = None
        plain = msg.get_payload(0, False)
        for part in msg.walk():
            ct = part.get_content_type()
            #if ct == 'application/x-pkcs7-signature':
            #    sig = part.get_payload(decode=True)
            #    break
            if ct == 'application/pkcs7-signature':
                sig = part.get_payload(decode=True)
                break
        #if sig is None:
        #    raise ValueError('not signed email')

        datau = plain.as_string().encode()
        #open(fixture('test_ssh_sign-plain.txt'),'wb').write(datau)

        datau = datau.replace(b'\n', b'\r\n')
        (hashok, signatureok, certok) = verifier.verify(sig, datau, [cert,])
        assert hashok and signatureok and certok
