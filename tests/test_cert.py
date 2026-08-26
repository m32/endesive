from __future__ import annotations

import os
import os.path
import sysconfig

import PyKCS11 as PK11
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive import hsm

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')


def fixture(fname):
    return os.path.join(fixtures_dir, fname)


dllpath = os.path.join(sysconfig.get_config_var('LIBDIR'), 'softhsm/libsofthsm2.so')

os.environ['SOFTHSM2_CONF'] = fixture('softhsm2.conf')
with open(fixture('softhsm2.conf'), 'wt') as _f:
    _f.write('''\
log.level = DEBUG
directories.tokendir = %s/softhsm2/
objectstore.backend = file
slots.removable = false
''' % fixtures_dir)

(
    ca_root_cert,
    ca_root_key,
    ca_sub_cert,
    ca_sub_key,
    cert1_csr,
    cert1_cert,
    cert1_key,
    cert1_pub,
    cert1_p12,
    cert2_csr,
    cert2_cert,
    cert2_key,
    cert2_pub,
    cert2_p12,
    cert3_csr,
    cert3_cert,
    cert3_key,
    cert3_pub,
    cert3_p12,
) = (
    fixture("ca/demo2_ca.root.crt.pem"),
    fixture("ca/demo2_ca.root.key.pem"),
    fixture("ca/demo2_ca.sub.crt.pem"),
    fixture("ca/demo2_ca.sub.key.pem"),
    fixture("ca/demo2_user1.csr.pem"),
    fixture("ca/demo2_user1.crt.pem"),
    fixture("ca/demo2_user1.key.pem"),
    fixture("ca/demo2_user1.pub.pem"),
    fixture("ca/demo2_user1.p12"),
    fixture("ca/demo2_user2.csr.pem"),
    fixture("ca/demo2_user2.crt.pem"),
    fixture("ca/demo2_user2.key.pem"),
    fixture("ca/demo2_user2.pub.pem"),
    fixture("ca/demo2_user2.p12"),
    fixture("ca/demo2_user3.csr.pem"),
    fixture("ca/demo2_user3.crt.pem"),
    fixture("ca/demo2_user3.key.pem"),
    fixture("ca/demo2_user3.pub.pem"),
    fixture("ca/demo2_user3.p12"),
)


class CA(object):
    def key_load(self, fname: str, password: str) -> rsa.RSAPrivateKey:
        with open(os.path.join("ca", fname), "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password.encode("utf-8"), default_backend()
            )
            return private_key

    def cert_load(self, fname: str) -> x509.Certificate:
        with open(os.path.join("ca", fname), "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def pk12_load(self, fname: str, password: str) -> pkcs12.PKCS12KeyAndCertificates:
        with open(os.path.join("ca", fname), "rb") as fp:
            return pkcs12.load_key_and_certificates(
                fp.read(), password.encode("utf-8"), default_backend()
            )

class HSMPrivateKey(rsa.RSAPrivateKey):
    def __init__(self, keypriv:PK11.CK_OBJECT_HANDLE, keypub: rsa.RSAPublicKey, session:PK11.Session):
        self._keypriv = keypriv
        self._keypub = keypub
        self.session = session

    def sign(self, data: bytes, padding, algorithm) -> bytes:
        #print("HSMPrivateKey.sign called with:", padding, algorithm)
        value = self.session.sign(
            self._keypriv, data, PK11.Mechanism(PK11.CKM_SHA256_RSA_PKCS, None)
        )
        value = bytes(bytearray(value))
        return value

    def private_key(self):
        return self._keypriv

    def public_key(self):
        return self._keypub

    @property
    def key_size(self) -> int:
        return self._keypub.key_size

    def make_error(self, *args, **kwargs):
        raise NotImplementedError("This method is not implemented for HSMPrivateKey.")

    __copy__ = make_error
    __deepcopy__ = make_error
    decrypt = make_error
    private_bytes = make_error
    private_numbers = make_error


class HSM(hsm.HSM):

    def __init__(self):
        super().__init__(dllpath)
        self.ca_id_root = bytes([0x1])
        self.ca_id_sub = bytes([0x2])
        self.ca_id_user = bytes([0x66, 0x66])

    def key_load(self, key_id:bytes) -> HSMPrivateKey|None:
        assert self.session, "Session is not initialized. Call login() first."

        key = self.session.findObjects(
            [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY), (PK11.CKA_ID, key_id)]
        )
        if len(key) == 0:
            return None
        key = key[0]

        modulus = self.session.getAttributeValue(key, [PK11.CKA_MODULUS])[0]
        modulus = binascii.hexlify(bytearray(modulus)).decode("utf-8")
        exponent = self.session.getAttributeValue(key, [PK11.CKA_PUBLIC_EXPONENT])[0]
        exponent = binascii.hexlify(bytearray(exponent)).decode("utf-8")

        key_pub = rsa.RSAPublicNumbers(
            e=int(exponent, 16),
            n=int(modulus, 16)
        ).public_key(backend=default_backend())

        return HSMPrivateKey(key, key_pub, self.session)

    def hsmsign(self, key: HSMPrivateKey, builder: x509.CertificateBuilder|x509.CertificateSigningRequestBuilder) -> bytes:
        assert self.session, "Session is not initialized. Call login() first."
        cert = builder.sign(
            key,
            hashes.SHA256(),
            default_backend()
        )
        #keyident = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        #print("Using key for authority_key_identifier and key_identifier:", keyident.digest)
        return cert.public_bytes(serialization.Encoding.DER)
