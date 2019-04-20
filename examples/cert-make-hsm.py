#!/usr/bin/env vpython3
# coding: utf-8

import os
import sys
import binascii
import datetime
import PyKCS11

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from asn1crypto import x509 as asn1x509
from asn1crypto import keys as asn1keys
from asn1crypto import pem as asn1pem

os.environ['SOFTHSM2_CONF'] = 'softhsm2.conf'
if not os.path.exists(os.path.join(os.getcwd(), 'softhsm2.conf')):
    open('softhsm2.conf', 'wt').write('''\
log.level = DEBUG
directories.tokendir = %s/softhsm2/
objectstore.backend = file
slots.removable = false
''' % os.getcwd())
if not os.path.exists(os.path.join(os.getcwd(), 'softhsm2')):
    os.mkdir(os.path.join(os.getcwd(), 'softhsm2'))

#
#!/bin/bash
#SOFTHSM2_CONF=softhsm2.conf
#softhsm2-util --label "endesive" --slot 1 --init-token --pin secret1 --so-pin secret2
#softhsm2-util --show-slots
#

if sys.platform == 'win32':
    dllpath = r'W:\binw\SoftHSM2\lib\softhsm2-x64.dll'
else:
    dllpath = '/usr/lib/softhsm/libsofthsm2.so'

class HSM:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(dllpath)
        self.session = None

    def getSlot(self, label):
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        for slot in slots:
            info = self.pkcs11.getTokenInfo(slot)
            try:
                if info.label.strip('\0') == label:
                    return slot
            except AttributeError:
                continue
        return None

    def create(self, label, pin, sopin):
        slot = self.getSlot(label)
        if slot is not None:
            return
        slot = self.pkcs11.getSlotList(tokenPresent=True)[-1]
        self.pkcs11.initToken(slot, sopin, label)
        session = self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        session.login(sopin, user_type=PyKCS11.CKU_SO)
        session.initPin(pin)
        session.logout()
        session.closeSession()

    def login(self, label, pin):
        slot = self.getSlot(label)
        if slot is None:
            return
        self.session = self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        self.session.login(pin)

    def logout(self):
        if self.session is not None:
            self.session.logout()
            self.session.closeSession()
            self.session = None

    def gen_privkey(self, label, key_id, key_length=2048):
        # label - just a label for identifying objects
        # key_id has to be the same for both objects, it will also be necessary
        #     when importing the certificate, to ensure it is linked with these keys.
        # key_length - key-length in bits

        public_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            (PyKCS11.CKA_MODULUS_BITS, key_length),
#            (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
            (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_VERIFY_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_ID, key_id)
#            (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
#            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
        ]

        private_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_SIGN_RECOVER, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, label),
            (PyKCS11.CKA_ID, key_id)
#            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        ]

        self.session.generateKeyPair(public_template, private_template)

    def cert_save(self, cert, label, subject, key_id):
        cert_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, label.encode('utf-8')),
            (PyKCS11.CKA_ID, key_id),  # must be set, and DER see Table 24, X.509 Certificate Object Attributes
            (PyKCS11.CKA_SUBJECT, subject.encode('utf-8')),  # must be set and DER, see Table 24, X.509 Certificate Object Attributes

            #(PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            #(PyKCS11.CKA_TRUSTED, PyKCS11.CK_TRUE),
            #(PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            #(PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            #(PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            #(PyKCS11.CKA_MODIFIABLE, PyKCS11.CK_TRUE),
#            (PyKCS11.CKA_ISSUER, cert.Issuer);
#            (PyKCS11.CKA_SERIAL_NUMBER,cert.SerialNumber)
            (PyKCS11.CKA_VALUE, cert),  # must be BER-encoded

        ]

        self.session.createObject(cert_template)

    def cert_load(self, keyID):
        rec = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_ID, keyID)])
        if len(rec) == 0:
            return None
        value = bytes(rec[0].to_dict()['CKA_VALUE'])
        return value

    def ca(self, sn, pubKey, privKey, label, subject, keyID):
        tbs = asn1x509.TbsCertificate({
            'version': 'v1',
            'serial_number': sn,
            'issuer': asn1x509.Name.build({
                'common_name': 'CA',
            }),
            'subject': asn1x509.Name.build({
                'common_name': 'CA',
            }),
            'signature': {
                'algorithm': 'sha256_rsa',
                'parameters': None,
            },
            'validity': {
                'not_before': asn1x509.Time({
                    'utc_time': datetime.datetime(2017, 1, 1, 0, 0),
                }),
                'not_after':  asn1x509.Time({
                    'utc_time': datetime.datetime(2038, 12, 31, 23, 59),
                }),
            },
            'subject_public_key_info': {
                'algorithm': {
                    'algorithm': 'rsa',
                    'parameters': None,
                },
                'public_key': pubKey
            }
        })

        # Sign the TBS Certificate
        data = tbs.dump()
        value = self.session.sign(privKey, data, PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None))
        value = bytes(bytearray(value))

        cert = asn1x509.Certificate({
            'tbs_certificate': tbs,
            'signature_algorithm': {
                'algorithm': 'sha256_rsa',
                'parameters': None,
            },
            'signature_value': value,
        })
        der_bytes = cert.dump()
        self.cert_save(der_bytes, label, subject, keyID)

    def ca_gen(self, label, keyID, subject):
        privKey = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, keyID)])[0]
        pubKey = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, keyID)])[0]

        pubKey = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, keyID)])[0]
        modulus = self.session.getAttributeValue(pubKey, [PyKCS11.CKA_MODULUS])[0]
        modulus = binascii.hexlify(bytearray(modulus)).decode("utf-8")
        exponent = self.session.getAttributeValue(pubKey, [PyKCS11.CKA_PUBLIC_EXPONENT])[0]
        exponent = binascii.hexlify(bytearray(exponent)).decode("utf-8")
        pubKey = asn1keys.RSAPublicKey({
            'modulus':int('0x'+modulus, 16),
            'public_exponent':int('0x'+exponent, 16)
        })
        #pubKey = asn1keys.RSAPublicKey.load(pubKey.dump())
        self.ca(1, pubKey, privKey, label, subject, keyID)

    def ca_export(self, label, keyID):
        der_bytes = self.cert_load(keyID)
        pem_bytes = asn1pem.armor('CERTIFICATE', der_bytes)
        open('cert.der', 'wb').write(der_bytes)
        # openssl x509 -inform der -in cert.der -text
        open('cert.pem', 'wb').write(pem_bytes)

    def main(self):
        label = 'ca'
        keyID = (0x1,)
        rec = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, keyID)])
        if len(rec) == 0:
            self.gen_privkey(label, keyID)
            self.ca_gen(label, keyID, 'CA')

        #rec = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_ID, keyID)])
        #self.ca_export(label, keyID)

def main():
    cls = HSM()
    cls.create("endesieve", "secret1", "secret2")
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()
main()
