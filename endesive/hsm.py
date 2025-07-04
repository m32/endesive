#!/usr/bin/env vpython3
# coding: utf-8

import os
import sys
import binascii
import datetime
import PyKCS11
import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from asn1crypto import x509 as asn1x509
from asn1crypto import keys as asn1keys
from asn1crypto import pem as asn1pem
from asn1crypto import util as asn1util

import paramiko.agent

import cryptography


class BaseHSM:
    def certificate(self):
        """
        callback for HSM
        used to identfy the ssh agents key exports via fingerprint

        :return: public-key-fingerprint, certificate-in-pem
        """
        raise NotImplementedError()

    def sign(self, keyid, data, mech):
        """
        sign

        :param keyid: the keyid as returned by certificate()
        :param data:
        :param mech: hash algo
        :return: PKCS7 signature blob
        """
        raise NotImplementedError()


class HSM(BaseHSM):
    def __init__(self, dllpath):
        """
        Initialize HSM

        :param dllpath: dynamic library used to communicate with HSM
        """
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(dllpath)
        self.session = None

    def getSlot(self, label):
        """
        Find the slot

        :param label: searched slot name
        :return: slot
        """
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        for slot in slots:
            info = self.pkcs11.getTokenInfo(slot)
            try:
                if info.label.split("\0")[0].strip() == label:
                    return slot
            except AttributeError:
                continue
        return None

    def create(self, label, pin, sopin):
        """
        Initialize a slot

        :param label: searched slot name
        :param pin: pin for slot
        :param sopin: administrative pin
        """
        slot = self.getSlot(label)
        if slot is not None:
            return
        slot = self.pkcs11.getSlotList(tokenPresent=True)[-1]
        self.pkcs11.initToken(slot, sopin, label)
        session = self.pkcs11.openSession(
            slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        session.login(sopin, user_type=PyKCS11.CKU_SO)
        session.initPin(pin)
        session.logout()
        session.closeSession()

    def login(self, label, pin):
        """
        Start session

        :param label: slot name
        :param pin: pin for slot
        """
        slot = self.getSlot(label)
        if slot is None:
            return
        self.session = self.pkcs11.openSession(
            slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login(pin)

    def logout(self):
        """
        End session
        """
        if self.session is not None:
            self.session.logout()
            self.session.closeSession()
            self.session = None

    def gen_privkey(self, label, key_id, key_length=2048):
        """
        Create private key

        :param label: key label
        :param key_id: key ID
        :param key_length: key length in bits
        """
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
        """
        Save certificate

        :param cert: certificate
        :param label: certificate label
        :param subject: certificate subject
        :param key_id: key ID
        """
        cert_template = [
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
            (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
            (PyKCS11.CKA_LABEL, label.encode("utf-8")),
            (
                PyKCS11.CKA_ID,
                key_id,
            ),  # must be set, and DER see Table 24, X.509 Certificate Object Attributes
            (
                PyKCS11.CKA_SUBJECT,
                subject.encode("utf-8"),
            ),  # must be set and DER, see Table 24, X.509 Certificate Object Attributes
            # (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
            # (PyKCS11.CKA_TRUSTED, PyKCS11.CK_TRUE),
            # (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_FALSE),
            # (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
            # (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
            # (PyKCS11.CKA_MODIFIABLE, PyKCS11.CK_TRUE),
            #            (PyKCS11.CKA_ISSUER, cert.Issuer);
            #            (PyKCS11.CKA_SERIAL_NUMBER,cert.SerialNumber)
            (PyKCS11.CKA_VALUE, cert),  # must be BER-encoded
        ]

        self.session.createObject(cert_template)

    def cert_load(self, keyID):
        """
        Load certificate

        :param keyID: key ID
        """
        rec = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_ID, keyID)]
        )
        if len(rec) == 0:
            return None
        value = bytes(rec[0].to_dict()["CKA_VALUE"])
        return value

    def certsign(self, sn, pubKey, subject, until, caprivKey, ca):
        """
        Sign certificate

        :param sn: serial number
        :param pubKey: public key
        :param subject: common name for certificate subject
        :param until: until when is the certificate valid
        :param caprivKey: signing key
        :param ca:

            None: create self signed root CA certificate

            True: create indirect CA certificate

            False: create user certificate
        """
        args = {
            "version": "v3",
            "serial_number": sn,
            "issuer": asn1x509.Name.build({
                "common_name": "hsm Root CA",
            }),
            "subject": asn1x509.Name.build({
                "common_name": subject,
            }),
            "signature": {
                "algorithm": "sha256_rsa",
                "parameters": None,
            },
            "validity": {
                "not_before": asn1x509.Time({
                    "utc_time": asn1x509.UTCTime((datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%y%m%d%H%M%SZ')),
                }),
                "not_after": asn1x509.Time({
                    "utc_time": asn1x509.UTCTime(until.strftime('%y%m%d%H%M%SZ')),
                }),
            },
            "subject_public_key_info": {
                "algorithm": {
                    "algorithm": "rsa",
                    "parameters": None,
                },
                "public_key": pubKey,
            },
        }
        if ca is None:
            args["issuer"] = asn1x509.Name.build({
                "common_name": subject,
            })
            args.update({
                "extensions": [
                    {
                        "extn_id": "basic_constraints",
                        "critical": True,
                        "extn_value": {"ca": True, "path_len_constraint": None},
                    },
                    {
                        "extn_id": "key_usage",
                        "critical": True,
                        "extn_value": set(
                            [
                                "crl_sign",
                                "digital_signature",
                                "key_cert_sign",
                            ]
                        ),
                    },
                ]
            })
        elif ca:
            extensions = [
                {
                #    'extn_id': 'crl_distribution_points',
                #    'critical': False,
                #    'extn_value': [
                #        asn1util.OrderedDict([
                #            ('distribution_point', ['http://ca.trisoft.com.pl/crl']),
                #            ('reasons', None),
                #            ('crl_issuer', None),
                #        ]),
                #    ]
                #}, {
                #    'extn_id':'authority_information_access',
                #    'critical': False,
                #    'extn_value': [
                #        {
                #            'access_method': 'ca_issuers',
                #            'access_location': asn1x509.URI('http://ca.trisoft.com.pl/cacert'),
                #        }, {
                #            'access_method': 'ocsp',
                #            'access_location': asn1x509.URI('http://ca.trisoft.com.pl/ocsp'),
                #        }
                #    ]
                #}, {
                    'extn_id': 'authority_key_identifier',
                    'critical': False,
                    'extn_value': {
                        'key_identifier': None,
                        'authority_cert_issuer': None,
                        'authority_cert_serial_number': 1,
                    }
                #}, {
                #    'extn_id': 'key_identifier',
                #    'critical': False,
                #    'extn_value': b'',
                }, {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": {"ca": True, "path_len_constraint": 0},
                }, {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": set([
                        "crl_sign",
                        "digital_signature",
                        "key_cert_sign",
                    ]),
                },
            ]
            args.update({
                "extensions": extensions
            })
        else:
            extensions = [
                #asn1util.OrderedDict([
                #    ('extn_id', 'subject_alt_name'),
                #    ('critical', False),
                #    ('extn_value', ['demo1@trisoft.com.pl'])
                #]),
                {
                #    'extn_id': 'subject_alt_name',
                #    'critical': False,
                #    'extn_value': {'rfc822_name' : 'demo1@trisoft.com.pl'},
                #}, {
                    'extn_id': 'authority_key_identifier',
                    'critical': False,
                    'extn_value': {
                        'key_identifier': None,
                        'authority_cert_issuer': None,
                        'authority_cert_serial_number': 2,
                    }
                #}, {
                #    'extn_id': 'key_identifier',
                #    'critical': False,
                #    'extn_value': b'',
                }, {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": {"ca": False},
                }, {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": set([
                            "digital_signature",
                            "key_agreement",
                            "key_encipherment",
                            "non_repudiation",
                    ]),
                },
            ]
            args.update({
                "issuer": asn1x509.Name.build({
                    "common_name": "hsm Indirect CA",
                }),
                "extensions": extensions,
            })

        tbs = asn1x509.TbsCertificate(args)

        # Sign the TBS Certificate
        data = tbs.dump()
        value = self.session.sign(
            caprivKey, data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        )
        value = bytes(bytearray(value))

        cert = asn1x509.Certificate(
            {
                "tbs_certificate": tbs,
                "signature_algorithm": {
                    "algorithm": "sha256_rsa",
                    "parameters": None,
                },
                "signature_value": value,
            }
        )
        return cert.dump()

    def ca_gen(self, label, keyID, subject):
        """
        Initiate root CA certificate

        :param label: HSM key label
        :param keyID: HSM key ID
        :param subject: common name in certificate subject
        """
        privKey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, keyID)]
        )[0]
        pubKey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, keyID)]
        )[0]

        modulus = self.session.getAttributeValue(pubKey, [PyKCS11.CKA_MODULUS])[0]
        modulus = binascii.hexlify(bytearray(modulus)).decode("utf-8")
        exponent = self.session.getAttributeValue(
            pubKey, [PyKCS11.CKA_PUBLIC_EXPONENT]
        )[0]
        exponent = binascii.hexlify(bytearray(exponent)).decode("utf-8")
        pubKey = asn1keys.RSAPublicKey(
            {
                "modulus": int("0x" + modulus, 16),
                "public_exponent": int("0x" + exponent, 16),
            }
        )
        # pubKey = asn1keys.RSAPublicKey.load(pubKey.dump())
        until = datetime.datetime.utcnow() + datetime.timedelta(
            days=365 * 40
        )
        der_bytes = self.certsign(1, pubKey, subject, until, privKey, None)
        self.cert_save(der_bytes, label, subject, keyID)

    def ca_sign(self, keyID, label, sn, subject, days, cakeyID):
        """
        Sign certificate

        :param keyID: HSM key identifier of the signed certificate
        :param label: HSM label
        :param sn: certificate serial number
        :param subject: HSM subject, common name stored in subject fiel of the signed certificate
        :param days: validity day of certificate
        :param cakeyID: HSM key identifier of the signing key
        """
        caprivKey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, cakeyID)]
        )[0]

        pubKey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, keyID)]
        )[0]
        modulus = self.session.getAttributeValue(pubKey, [PyKCS11.CKA_MODULUS])[0]
        modulus = binascii.hexlify(bytearray(modulus)).decode("utf-8")
        exponent = self.session.getAttributeValue(
            pubKey, [PyKCS11.CKA_PUBLIC_EXPONENT]
        )[0]
        exponent = binascii.hexlify(bytearray(exponent)).decode("utf-8")
        pubKey = asn1keys.RSAPublicKey(
            {
                "modulus": int("0x" + modulus, 16),
                "public_exponent": int("0x" + exponent, 16),
            }
        )
        # pubKey = asn1keys.RSAPublicKey.load(pubKey.dump())
        until = datetime.datetime.utcnow() + datetime.timedelta(
            days=days
        )
        der_bytes = self.certsign(sn, pubKey, subject, until, caprivKey, keyID == b'\x02')
        self.cert_save(der_bytes, label, subject, keyID)

    def cert_export(self, fname, keyID):
        der_bytes = self.cert_load(keyID)
        pem_bytes = asn1pem.armor("CERTIFICATE", der_bytes)
        with open(fname + ".der", "wb") as fp:
            fp.write(der_bytes)
        with open(fname + ".pem", "wb") as fp:
            fp.write(pem_bytes)


class SSHAgentHSM(BaseHSM):
    def __init__(self, cert):
        assert isinstance(cert, cryptography.x509.Certificate)
        self._a = paramiko.agent.Agent()
        self._cert = cert

    def close(self):
        self._a.close()

    def certificate(self):
        """
        callback for HSM
        used to identfy the ssh agents key exports via fingerprint

        :return: public-key-fingerprint, certificate-in-pem
        """

        # https://superuser.com/questions/421997/what-is-a-ssh-key-fingerprint-and-how-is-it-generated
        # convert RSA Key to SSH Fingerprint
        alg, key = (
            self._cert.public_key()
            .public_bytes(
                encoding=cryptography.hazmat.primitives.serialization.Encoding.OpenSSH,
                format=cryptography.hazmat.primitives.serialization.PublicFormat.OpenSSH,
            )
            .split(b" ")
        )

        fp = b"SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(key)).digest()
        )
        cert = self._cert.public_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM
        )

        return fp, cert

    @staticmethod
    def _decode_fp(keyfp):
        """
        decode a fingerprint

        :param keyfp: key fingerprint in OpenSSH Format
        :return: alg, fingerprint-binary
        """
        if not isinstance(keyfp, str):
            keyfp = keyfp.decode()
        alg, other = keyfp.split(":", 1)
        if alg == "SHA256":
            # pad base64 data
            data = other.encode() + b"=" * (-len(other) % 4)
            fp = base64.b64decode(data)
        elif alg == "MD5":
            data = other.replace(":", " ")
            fp = bytes.fromhex(data)
        else:
            raise ValueError(alg)
        return alg.lower(), fp

    def key(self, fp):
        """
        lookup a ssh-agent-exported key using fingerprint

        :param fp: the fingerprint
        :return: the key on success
        """

        alg, fp = self._decode_fp(fp)
        for key in self._a.get_keys():
            kfp = getattr(hashlib, alg)(key.asbytes()).digest()
            if kfp == fp:
                break
        else:
            raise ValueError("Key not found")
        return key

    def sign(self, keyid, data, hashalgo):
        """
        sign using ssh-agent sign_data
        creates RSA signature with padding=PKCS1v15 alg=SHA1

        :param keyid: the keyid as returned by certificate()
        :param data:
        :param hashalgo: has to be sha1, sha256 or sha512
        :return: PKCS7 signature blob
        """
        assert hashalgo in ("sha1", "sha256", "sha512")

        if not isinstance(data, bytes):
            data = data.encode()

        # defined in
        # SSH Agent Protocol draft-miller-ssh-agent-00 5.3.  Signature flags
        # https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-5.3
        flags = {
            "sha1": 0,
            "sha256": 2,  # SSH_AGENT_RSA_SHA2_256
            "sha512": 4,  # SSH_AGENT_RSA_SHA2_512
        }[hashalgo]

        key = self.key(keyid)

        # AgentKey.sign_ssh_data is padding=PKCS1v15 alg=SHA1
        # paramiko does not expose the ssh-agent sign flags to use sha2-256/512
        # re-implement sign_ssh_agent ..
        msg = paramiko.message.Message()
        msg.add_byte(paramiko.agent.cSSH2_AGENTC_SIGN_REQUEST)
        msg.add_string(key.blob)
        msg.add_string(data)
        msg.add_int(flags)
        ptype, result = self._a._send_message(msg)
        if ptype != paramiko.agent.SSH2_AGENT_SIGN_RESPONSE:
            raise paramiko.SSHException("key cannot be used for signing")
        d = paramiko.message.Message(result.get_binary())

        # parse operation result
        alg = d.get_text()

        # interpret
        if alg in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
            sig = d.get_binary()
        else:
            raise ValueError(alg)
        return sig
