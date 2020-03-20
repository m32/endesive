#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import os
import stat
import subprocess
import datetime
import base64
import email

from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
from email.mime.base import MIMEBase

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.hsm import SSHAgentHSM
from endesive import signer


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
    del body['MIME-Version']
    env.attach(body)

    app = MIMEApplication(open(Attachment, 'rb').read(), _subtype="pdf")
    app.add_header('content-disposition', 'attachment', filename=Attachment)
    env.attach(app)

    msg.attach(env)

    sig = MIMEBase(_maintype='application', _subtype='pkcs7-signature', name="smime.p7s")
    sig.add_header('Content-Disposition', 'attachment', filename='smime.p7s')
    sig.add_header('Content-Transfer-Encoding', 'base64')
    sig.set_payload(signer(env.as_string().encode()))
    del sig['MIME-Version']
    msg.attach(sig)

    return msg, env, sig


def sign(datau, key, cert, othercerts, hashalgo, hsm):
    datau = datau.replace(b'\n', b'\r\n')
    datas = signer.sign(datau, key, cert, othercerts, hashalgo, attrs=True, pss=False, hsm=hsm)
    return base64.encodebytes(datas)


def main():
    # split certificate
    # we need the key as seperate file
    with open('demo2_user1.p12', 'rb') as fp:
        key, cert, othercerts = pkcs12.load_key_and_certificates(fp.read(), b'1234', backends.default_backend())

    agent = SSHAgentHSM(cert)

    # lookup the ssh fingerprint for the certificates public key
    keyid, _ = agent.certificate()
    keyfile = None
    try:
        # is the public key known to the ssh-agent yet?
        agent.key(keyid)
    except ValueError:

        # set file permissions to something ssh-agent accepts
        def perms(path):
            if stat.S_IMODE(os.stat(path).st_mode) & ~stat.S_IRWXU:
                os.chmod(path, (stat.S_IRUSR | stat.S_IWUSR))


        # we have to add the key to the ssh-agent
        # remove the key password, dump in traditional openssl so ssh-agent can add the key
        keyfile = 'demo2_user1.key.nopass.pem'
        with open(keyfile, 'wb') as fp:
            # dump the key
            fp.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        perms(keyfile)

        # pub file so ssh-add -d can be used
        pubfile = 'demo2_user1.key.nopass.pem.pub'
        with open(pubfile, 'wb') as fp:
            # convert the public key of the certificate to ssh public key format
            fp.write(cert.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ))
        perms(pubfile)

        subprocess.call(["ssh-add", keyfile])

        # reconnect the agent so the key is visible to paramiko
        agent = SSHAgentHSM(cert)


    datau = open('smime-unsigned.txt', 'rb').read()

    msg, env, sig = compose(
        From='root+from@localhost',
        To='root+to@localhost',
        Subject='this is the subject',
        Body=datau,
        Attachment='pdf-acrobat.pdf',
        signer=lambda data: sign(data, None, cert, othercerts, 'sha256', agent)
    )
    datas = msg.as_bytes(unixfrom=True)
    open('smime-signed-hsm.txt', 'wb').write(datas)

    # we added, so we remove the key from ssh-agent
    if keyfile:
        subprocess.call(['ssh-add', '-d', keyfile])

main()
