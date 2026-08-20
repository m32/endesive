# Source - https://stackoverflow.com/q/78809096
# Posted by BTheOne
# Retrieved 2026-08-06, License - CC BY-SA 4.0

import imaplib
import email
from email.header import decode_header
from OpenSSL import crypto
import time, datetime

# Email receiving configuration
imap_server = "imap.mail.me.com" # <-- iCloud's mail IMAP
imap_user = "example@example.com" # <- Email
imap_password = "example_password" # <-- Email App-Specific password

# Paths to your certificate and private key
cert_path = 'path\to\my\certificate.pem' #<-- Path to cert.pem
key_path = 'path\to\my\privatekey.pem' # <-- Path to privkey.pem

# Function to decrypt S/MIME email
def decrypt_smime(encrypted_message):
    try:
        # Load the certificate and private key
        with open(cert_path, 'rb') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        with open(key_path, 'rb') as f:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

        # Create a Crypto object and decrypt the email
        smime = crypto.SMIME()
        smime.load_cert(cert)
        smime.load_key(key)
        decrypted_message = smime.decrypt(encrypted_message)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        print(f"Error decrypting S/MIME email: {e}")
        return None

# Function to process email payload
def process_email_payload(msg):
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "application/pkcs7-mime":
                payload = part.get_payload(decode=True)
                payload = decrypt_smime(payload)
                if payload:
                    return payload.strip()
            elif content_type in ["text/plain", "text/html"]:
                payload = part.get_payload(decode=True).strip()
                return payload.decode('utf-8')
    else:
        payload = msg.get_payload(decode=True)
        if msg.get_content_type() == "application/pkcs7-mime":
            payload = decrypt_smime(payload)
        return payload.decode('utf-8')
    return None

# Function to check for new emails
def check_email():
    try:
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(imap_user, imap_password)
        mail.select("inbox")

        result, data = mail.search(None, "UNSEEN")

        # Debugging information
        print(f"Search result {datetime.datetime.now():%H.%M.%S}: {result}") # <-- Also prints current time so I can differentiate the different outputs
        print(f"Search data: {data}")

        if result != "OK":
            print(f"Error searching Inbox: {result}")
            return

        if data[0] is None:
            print("No new emails.")
            return

        email_ids = data[0].split()
        if not email_ids:
            print("No new emails.")
            return

        print(f"Email IDs: {email_ids}")  # Debug email IDs

        for email_id in email_ids:
            result, msg_data = mail.fetch(email_id, "(RFC822)")
            print(f"Fetch result: {result}")  # Debug fetch result
            print(f"Fetch msg_data: {msg_data}")  # Debug msg_data

            if result != "OK":
                print(f"Error fetching email ID {email_id}: {result}")
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    raw_email = response_part[1]
                    print(f"Raw email: {raw_email}")  # Debug raw email data
                    try:
                        msg = email.message_from_bytes(raw_email)
                        subject, encoding = decode_header(msg["Subject"])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding if encoding else 'utf-8')
                        sender = email.utils.parseaddr(msg["From"])[1]

                        print(f"Subject: {subject}")
                        print(f"From: {sender}")

                        payload = process_email_payload(msg)
                        if payload:
                            print(f"Payload: {payload}")  # Debug payload content
                        else:
                            print(f"Could not decode payload for email ID {email_id}")
                            continue

                        if "test" in payload:
                            print("Test prompt received")

                    except Exception as e:
                        print(f"Error decoding email ID {email_id}: {e}")
                        continue

        mail.close()
        mail.logout()
    except Exception as e:
        print(f"Failed to check email: {e}")

# Actually try to check and decode emails (loop)
while True:
    check_email()
    time.sleep(10)
