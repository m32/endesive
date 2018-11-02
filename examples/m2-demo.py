#!/usr/bin/env vpython2
import os
import os.path
import smtplib
import datetime

from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

from M2Crypto import BIO, Rand, SMIME, X509

randpool = '/tmp/randpool.dat'

ca_cert = 'demo2_ca.crt.pem'
# we need to have access to both keys
signer_key  = 'demo2_user1.key.pem'
signer_cert = 'demo2_user1.crt.pem'
recipient_key  = 'demo2_user2.key.pem'
recipient_cert = 'demo2_user2.crt.pem'

def makebuf(text):
    return BIO.MemoryBuffer(text)

class Demo:
    def sign(self):

        # Make a MemoryBuffer of the message.
        buf = makebuf('a sign of our times')

        # Seed the PRNG.
        Rand.load_file(randpool, -1)

        # Instantiate an SMIME object; set it up; sign the buffer.
        s = SMIME.SMIME()
        s.load_key(signer_key, signer_cert)

        p7 = s.sign(buf, SMIME.PKCS7_DETACHED)

        # Recreate buf.
        buf = makebuf('a sign of our times')

        # Output p7 in mail-friendly format.
        out = BIO.MemoryBuffer()
        out.write('From: sender@example.dom\n')
        out.write('To: recipient@example.dom\n')
        out.write('Subject: M2Crypto S/MIME testing\n')

        s.write(out, p7, buf)

        result = out.read()

        # Save the PRNG's state.
        Rand.save_file(randpool)

        open('smime-m2-sign.txt', 'wt').write(result)

    def verify(self):

        # Instantiate an SMIME object.
        s = SMIME.SMIME()

        # Load the signer's cert.
        x509 = X509.load_cert(signer_cert)
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)

        # Load the signer's CA cert.
        st = X509.X509_Store()
        st.load_info(ca_cert)
        s.set_x509_store(st)

        # Load the data, verify it.
        p7, data = SMIME.smime_load_pkcs7('smime-m2-sign.txt')
        v = s.verify(p7)

        print v
        print data
        print data.read()

    def encrypt(self):

        # Make a MemoryBuffer of the message.
        buf = makebuf('a sign of our times')

        # Seed the PRNG.
        Rand.load_file(randpool, -1)

        # Instantiate an SMIME object.
        s = SMIME.SMIME()

        # Load target cert to encrypt to.
        x509 = X509.load_cert(recipient_cert)
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)

        # Set cipher: 3-key triple-DES in CBC mode.
        s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

        # Encrypt the buffer.
        p7 = s.encrypt(buf)

        # Output p7 in mail-friendly format.
        out = BIO.MemoryBuffer()
        out.write('From: sender@example.dom\n')
        out.write('To: recipient@example.dom\n')
        out.write('Subject: M2Crypto S/MIME testing\n')
        s.write(out, p7)

        result = out.read()

        # Save the PRNG's state.
        Rand.save_file(randpool)

        open('smime-m2-encrypt.txt', 'wt').write(result)

    def decrypt(self):
        # Instantiate an SMIME object.
        s = SMIME.SMIME()

        # Load private key and cert.
        s.load_key(recipient_key, recipient_cert)

        # Load the encrypted data.
        p7, data = SMIME.smime_load_pkcs7('smime-m2-encrypt.txt')

        # Decrypt p7.
        out = s.decrypt(p7)

        print out

    def sign_and_encrypt(self):

        # Make a MemoryBuffer of the message.
        buf = makebuf('a sign of our times')

        # Seed the PRNG.
        Rand.load_file(randpool, -1)

        # Instantiate an SMIME object.
        s = SMIME.SMIME()

        # Load signer's key and cert. Sign the buffer.
        s.load_key(signer_key, signer_cert)
        p7 = s.sign(buf, SMIME.PKCS7_DETACHED)

        # Load target cert to encrypt the signed message to.
        x509 = X509.load_cert(recipient_cert)
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)

        # Set cipher: 3-key triple-DES in CBC mode.
        s.set_cipher(SMIME.Cipher('des_ede3_cbc'))

        # Create a temporary buffer.
        tmp = BIO.MemoryBuffer()

        # Write the signed message into the temporary buffer.
        s.write(tmp, p7, buf)

        # Encrypt the temporary buffer.
        p7 = s.encrypt(tmp)

        # Output p7 in mail-friendly format.
        out = BIO.MemoryBuffer()
        out.write('From: sender@example.dom\n')
        out.write('To: recipient@example.dom\n')
        out.write('Subject: M2Crypto S/MIME testing\n')
        s.write(out, p7)

        result = out.read()

        # Save the PRNG's state.
        Rand.save_file(randpool)

        open('smime-m2-sign-encrypt.txt', 'wt').write(result)

    def decrypt_and_verify(self):
        # Instantiate an SMIME object.
        s = SMIME.SMIME()

        # Load private key and cert.
        s.load_key(recipient_key, recipient_cert)

        # Load the signed/encrypted data.
        p7, data = SMIME.smime_load_pkcs7('smime-m2-sign-encrypt.txt')

        # After the above step, 'data' == None.
        # Decrypt p7. 'out' now contains a PKCS #7 signed blob.
        out = s.decrypt(p7)

        # Load the signer's cert.
        x509 = X509.load_cert(signer_cert)
        sk = X509.X509_Stack()
        sk.push(x509)
        s.set_x509_stack(sk)

        # Load the signer's CA cert.
        st = X509.X509_Store()
        st.load_info(ca_cert)
        s.set_x509_store(st)

        # Recall 'out' contains a PKCS #7 blob.
        # Transform 'out'; verify the resulting PKCS #7 blob.
        p7_bio = BIO.MemoryBuffer(out)
        p7, data = SMIME.smime_load_pkcs7_bio(p7_bio)
        v = s.verify(p7)

        print v

    def sign_and_attachment(self):
        server = 'mail.example.dom'
        sender = 'sender@example.dom'
        to = ['recipient@example.dom',]
        subject = 'test'
        text = 'test message'
        files=['m2-demo.py']
        attachments={}
        bcc=[]


        if isinstance(to,str):
            to = [to]

        # create multipart message
        msg = MIMEMultipart()

        # attach message text as first attachment
        msg.attach( MIMEText(text) )

        # attach files to be read from file system
        for file in files:
            part = MIMEBase('application', "octet-stream")
            part.set_payload( open(file,"rb").read() )
            Encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="%s"'
                           % os.path.basename(file))
            msg.attach(part)

        # attach filest read from dictionary
        for name in attachments:
            part = MIMEBase('application', "octet-stream")
            part.set_payload(attachments[name])
            Encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment; filename="%s"' % name)
            msg.attach(part)

        # put message with attachments into into SSL' I/O buffer
        msg_str = msg.as_string()
        buf = BIO.MemoryBuffer(msg_str)

        # load seed file for PRNG
        Rand.load_file(randpool, -1)

        smime = SMIME.SMIME()

        # load certificate
        smime.load_key(signer_key, signer_cert)

        # sign whole message
        p7 = smime.sign(buf, SMIME.PKCS7_DETACHED)

        # create buffer for final mail and write header
        out = BIO.MemoryBuffer()
        out.write('From: %s\n' % sender)
        out.write('To: %s\n' % COMMASPACE.join(to))
        out.write('Date: %s\n' % formatdate(localtime=True))
        out.write('Subject: %s\n' % subject)
        out.write('Auto-Submitted: %s\n' % 'auto-generated')

        # convert message back into string
        buf = BIO.MemoryBuffer(msg_str)

        # append signed message and original message to mail header
        smime.write(out, p7, buf)

        # load save seed file for PRNG
        Rand.save_file(randpool)

        # extend list of recipents with bcc adresses
        to.extend(bcc)

        result = out.read()

        open('smime-m2-attachment.txt', 'wt').write(result)
        return

        # finaly send mail
        smtp = smtplib.SMTP(server)
        smtp.sendmail(sender, to, result )
        smtp.close()

def main():
    cls = Demo()

    if 0:
        cls.sign()
        cls.encrypt()
        cls.sign_and_encrypt()
        cls.sign_and_attachment()

    cls.verify()
    cls.decrypt()
    cls.decrypt_and_verify()

main()
