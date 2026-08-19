#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import os
import sys
import sysconfig
import binascii
import datetime
import shutil


if "--force" in sys.argv:
    if os.path.exists(os.path.join(os.getcwd(), 'softhsm2')):
        shutil.rmtree(os.path.join(os.getcwd(), 'softhsm2'))

from endesive import hsm
import PyKCS11 as PK11
from hsm_config_softhsm import DLLPATH

from asn1crypto import x509 as asn1x509

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

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

    def __init__(self, dllpath: str, ca_url_prefix: str):
        super().__init__(dllpath)
        self.ca_id_root = bytes([0x1])
        self.ca_id_sub = bytes([0x2])
        self.ca_id_user = bytes([0x66, 0x66])
        self.ca_url_prefix = ca_url_prefix

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
        if 1:
            cert = builder.sign(
                key,
                hashes.SHA256(),
                default_backend()
            )
            #keyident = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
            #print("Using key for authority_key_identifier and key_identifier:", keyident.digest)
            return cert.public_bytes(serialization.Encoding.DER)
        # cryptography's CertificateBuilder does not expose public_bytes, so build a temporary certificate to obtain the
        # DER-encoded TBSCertificate bytes that the HSM signs.
        dummy_key = rsa.generate_private_key(
            public_exponent=key.public_key().public_numbers().e,
            key_size=key.public_key().key_size,
            backend=default_backend(),
        )
        dummy_cert = builder.sign(
            dummy_key,
            hashes.SHA256(),
            default_backend()
        )
        data = dummy_cert.public_bytes(serialization.Encoding.DER)
        tbs = asn1x509.Certificate.load(data)["tbs_certificate"]
        if isinstance(builder, x509.CertificateBuilder):
            if 1:
                print('dummy key:',dummy_key)
                keyinfo = dummy_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                keyident = hashes.Hash(hashes.SHA1(), backend=default_backend())
                keyident.update(keyinfo)
                keyident = keyident.finalize()
                print("Using dummy key for authority_key_identifier and key_identifier:", keyident)
            else:
                keyident = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                for ext in tbs["extensions"]:
                    if ext["extn_id"].native == "authority_key_identifier":
                        ext['extn_value'].native['key_identifier'] = keyident
                        print("Updated authority_key_identifier with keypub:", keyident)
                    elif ext["extn_id"].native == "key_identifier":
                        ext['extn_value'] = keyident
                        print("Updated key_identifier with keypub:", keyident)

        signature = self.session.sign(
            key.private_key(), tbs.dump(), PK11.Mechanism(PK11.CKM_SHA256_RSA_PKCS, None)
        )
        cert = asn1x509.Certificate(
            {
                "tbs_certificate": tbs,
                "signature_algorithm": {
                    "algorithm": "sha256_rsa",
                    "parameters": None,
                },
                "signature_value": bytes(bytearray(signature)),
            }
        )
        return cert.dump()
    
    def csr_create(
        self,
        email: str,
        key: HSMPrivateKey,
        country: str|None = None,
        state: str|None = None,
        locality: str|None = None,
        organization: str|None = None,
        commonname: str|None = None,
    ) -> bytes:
        names = []
        for t, v in (
            (NameOID.COUNTRY_NAME, country),
            (NameOID.STATE_OR_PROVINCE_NAME, state),
            (NameOID.LOCALITY_NAME, locality),
            (NameOID.ORGANIZATION_NAME, organization),
            (NameOID.COMMON_NAME, commonname),
        ):
            if v:
                names.append(x509.NameAttribute(t, v))
        names.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
        builder = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name(names))
        )
        data = self.hsmsign(key, builder)
        return data

    def csr_sign(self, csrdata: bytes) -> bytes:
        keysub = self.key_load(self.ca_id_sub)
        assert keysub is not None, "Failed to load CA sub private key."
        data = self.cert_load(self.ca_id_sub)
        assert data is not None, "Failed to load CA sub certificate."
        certsub = x509.load_der_x509_certificate(data, default_backend())

        csr = x509.load_der_x509_csr(csrdata, default_backend())
        emails = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        assert len(emails) == 1, "CSR does not contain an email address."
        assert isinstance(emails[0].value, str), "CSR email address is not a string."
        assert '@' in emails[0].value, "CSR email address does not contain an '@' symbol."

        names = [
            x509.RFC822Name(emails[0].value),
            #x509.DNSName('trisoft.com.pl'),
        ]
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(certsub.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    keysub.public_key()
                ),
                critical=False,
            ).add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[
                                x509.UniformResourceIdentifier(
                                    f"{self.ca_url_prefix}/crl"
                                )
                            ],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            ).add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.OID_CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                f"{self.ca_url_prefix}/cert"
                            ),
                        ),
                        x509.AccessDescription(
                            x509.OID_OCSP,
                            x509.UniformResourceIdentifier(
                                f"{self.ca_url_prefix}/ocsp"
                            ),
                        ),
                    ]
                ),
                critical=False,
            ).add_extension(
                x509.SubjectAlternativeName(names),
                critical=False,
            ).add_extension(
                # certificate_policies
                x509.ExtendedKeyUsage([
                    x509.OID_CLIENT_AUTH, # 1.3.6.1.5.5.7.3.2
                    #x509.OID_SERVER_AUTH,
                    x509.OID_EMAIL_PROTECTION,
                    x509.ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"), # document signing
                    x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36"), # document signing
                    #x509.ObjectIdentifier("1.3.6.1.5.5.7.3.21"), # ssh client
                    #x509.ObjectIdentifier("1.3.6.1.5.5.7.3.22"), # ssh server
                    #1.2.840.113583.1.1.7.1.0 .. 11 # https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/oids.html
                ]),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    # Digital Signature: Indicates that the key can be used for digital signatures to verify the authenticity and integrity of data. 
                    digital_signature=True,
                    # Non-Repudiation: Used in conjunction with digital signatures to provide an additional layer of protection against denial of signature. 
                    content_commitment=True,  # nonRepudiation
                    # Key Encipherment: Specifies that the key can be used for encrypting other keys, typically for key transport. 
                    key_encipherment=True,
                    # Data Encipherment: Indicates that the key can be used for data encryption and decryption. 
                    data_encipherment=True,
                    # Key Agreement: Used when the key is involved in key exchange agreements, such as Diffie-Hellman. 
                    key_agreement=True,
                    # Encipher Only: Specifies that the key can only be used for encryption, not decryption. 
                    encipher_only=False,
                    # Decipher Only: Specifies that the key can only be used for decryption, not encryption. 
                    decipher_only=False,
                    # ca
                    # Certificate Signing: Specifies that the key can be used to sign other certificates, typically used by Certificate Authorities. 
                    key_cert_sign=False,
                    # CRL Signing: Indicates that the key can be used to sign Certificate Revocation Lists (CRLs). 
                    crl_sign=False,
                ),
                critical=True,
            )
        )

        data = self.hsmsign(keysub, builder)
        return data

    def ca_createroot(self, key: HSMPrivateKey) -> bytes:
        assert self.session, "Session is not initialized. Call login() first."

        subject = issuer = x509.Name(
            [
            x509.NameAttribute(NameOID.COMMON_NAME, "CA Root"),
            ]
        )

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                # Our certificate will be valid for 40 years
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=40 * 365)
            ).add_extension(
                x509.BasicConstraints(
                    ca=True,
                    path_length=None,  # pathlen: is equal to the number of CAs/ICAs it can sign
                ),
                critical=True,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,  # nonRepudiation
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                    # ca
                    key_cert_sign=True,
                    crl_sign=True,
                ),
                critical=True,
            )
        )

        data = self.hsmsign(key, builder)
        return data

    def ca_createsub(self, key: HSMPrivateKey, rootcert: x509.Certificate, rootkey: HSMPrivateKey) -> bytes:
        subject = x509.Name(
            [
            x509.NameAttribute(NameOID.COMMON_NAME, "AA TriSoft Intermediate CA"),
            ]
        )
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(rootcert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                # Our certificate will be valid for 10 years
                datetime.datetime.now(datetime.UTC)
                + datetime.timedelta(days=10 * 365)
            ).add_extension(
                x509.BasicConstraints(
                    ca=True,
                    path_length=0,  # pathlen: is equal to the number of CAs/ICAs it can sign
                ),
                critical=True,
            ).add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[
                                x509.UniformResourceIdentifier(
                                    f"{self.ca_url_prefix}/crl"
                                )
                            ],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            ).add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.OID_CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                f"{self.ca_url_prefix}/cacert"
                            ),
                        ),
                        x509.AccessDescription(
                            x509.OID_OCSP,
                            x509.UniformResourceIdentifier(
                                f"{self.ca_url_prefix}/ocsp"
                            ),
                        ),
                    ]
                ),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    rootcert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
                critical=False,
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,  # nonRepudiation
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                    # ca
                    key_cert_sign=True,
                    crl_sign=True,
                ),
                critical=True,
            )
        )

        data = self.hsmsign(rootkey, builder)
        return data

    def USER(self, no) -> None:
        assert self.session, "Session is not initialized. Call login() first."

        label = f'HSM User {no}'
        keyid  = self.ca_id_user+bytes((no,))
        keyuser = self.key_load(keyid)
        if keyuser is None:
            self.gen_privkey(label, keyid)
            keyuser = self.key_load(keyid)
        assert keyuser is not None, "Failed to load or create USER private key."
        data = self.cert_load(keyid)
        if data is None:
            csrdata = self.csr_create(
                f"demo{no}@trisoft.com.pl",
                keyuser,
                commonname='trisoft.com.pl',
            )
            data = self.csr_sign(csrdata)
            self.cert_save(data, label, label, keyid)
        self.cert_export(f'cert-hsm-user-{no}', keyid)

    def cert_export(self, fname, key_id):
        data = self.cert_load(key_id)
        assert data is not None, "Failed to load certificate."
        cert = x509.load_der_x509_certificate(data, default_backend())
        with open(fname + ".der", "wb") as fp:
            fp.write(cert.public_bytes(serialization.Encoding.DER))
        with open(fname + ".pem", "wb") as fp:
            fp.write(cert.public_bytes(serialization.Encoding.PEM))

    def USERs(self):
        self.USER(1)
        self.USER(2)
        self.USER(3)

    def CA(self):
        assert self.session, "Session is not initialized. Call login() first."

        label = 'CA Root'
        keyroot = self.key_load(self.ca_id_root)
        if keyroot is None:
            self.gen_privkey(label, self.ca_id_root)
            keyroot = self.key_load(self.ca_id_root)
        assert keyroot is not None, "Failed to load or create CA root private key."
        data = self.cert_load(self.ca_id_root)
        if data is None:
            data = self.ca_createroot(keyroot)
            self.cert_save(data, label, label, self.ca_id_root)

        certroot = x509.load_der_x509_certificate(data, default_backend())
        self.cert_export('cert-hsm-ca-root', self.ca_id_root)

        label = 'CA Sub'
        keysub = self.key_load(self.ca_id_sub)
        if keysub is None:
            self.gen_privkey(label, self.ca_id_sub)
            keysub = self.key_load(self.ca_id_sub)
        assert keysub is not None, "Failed to load or create CA sub private key."
        data = self.cert_load(self.ca_id_sub)
        if data is None:
            data = self.ca_createsub(keysub, certroot, keyroot)
            self.cert_save(data, label, label, self.ca_id_sub)
        # certsub = x509.load_der_x509_certificate(data, default_backend())
        self.cert_export('cert-hsm-ca-sub', self.ca_id_sub)

    def main(self):
        self.CA()
        self.USERs()

def main():
    print("Generating HSM certificates")
    cls = HSM(DLLPATH, 'https://ca.trisoft.com.pl/api')
    cls.create("endesieve", "secret1", "secret2")
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()
main()
