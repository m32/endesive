#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import typing
import datetime
import os, os.path
import sys
import glob
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

force = "--force" in sys.argv

(
    ca,
    ca_key,
    cert1,
    cert1_key,
    cert1_pub,
    cert1_p12,
    cert2,
    cert2_key,
    cert2_pub,
    cert2_p12,
) = (
    "demo2_ca.crt.pem",
    "demo2_ca.key.pem",
    "demo2_user1.crt.pem",
    "demo2_user1.key.pem",
    "demo2_user1.pub.pem",
    "demo2_user1.p12",
    "demo2_user2.crt.pem",
    "demo2_user2.key.pem",
    "demo2_user2.pub.pem",
    "demo2_user2.p12",
)


class Main(object):
    def key_create(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

    def key_save(self, fname: str, key: rsa.RSAPrivateKey, password: str) -> None:
        # Write our key to disk for safe keeping
        with open(os.path.join("ca", fname), "wb") as f:
            if not password:
                f.write(
                    key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            else:
                f.write(
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.BestAvailableEncryption(
                            password.encode("utf-8")
                        ),
                    )
                )

    def key_load(self, fname: str, password: str) -> rsa.RSAPrivateKey:
        with open(os.path.join("ca", fname), "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password.encode("utf-8"), default_backend()
            )
            return private_key

    def cert_save(self, fname: str, data: x509.Certificate) -> None:
        with open(os.path.join("ca", fname), "wb") as f:
            f.write(data.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join("ca", fname) + ".cer", "wb") as f:
            f.write(data.public_bytes(serialization.Encoding.DER))
        cwd = os.getcwd()
        os.chdir("ca")
        os.symlink(fname, str(data.serial_number))
        os.chdir(cwd)

    def cert_load(self, fname: str) -> x509.Certificate:
        with open(os.path.join("ca", fname), "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())

    def csr_load(self, fname: str) -> x509.CertificateSigningRequest:
        with open(os.path.join("ca", fname), "rb") as f:
            return x509.load_pem_x509_csr(data=f.read(), backend=default_backend())

    def csr_create(
        self,
        email: str,
        key: rsa.RSAPrivateKey,
        country: typing.Union[str, None] = None,
        state: typing.Union[str, None] = None,
        locality: typing.Union[str, None] = None,
        organization: typing.Union[str, None] = None,
        commonname: typing.Union[str, None] = None,
    ) -> x509.CertificateSigningRequest:
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
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name(names))
            .sign(
                # Sign the CSR with our private key.
                key,
                hashes.SHA256(),
                default_backend(),
            )
        )

    def csr_sign(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        emails = csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        names = [x509.RFC822Name(emails[0].value)]
        return (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(uuid.uuid4().int)  # pylint: disable=no-member
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_pk.public_key()
                ),
                critical=False,
            )
            .add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[
                                x509.UniformResourceIdentifier(
                                    "http://ca.trisoft.com.pl/crl"
                                )
                            ],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        )
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.AuthorityInformationAccess(
                    [
                        x509.AccessDescription(
                            x509.OID_CA_ISSUERS,
                            x509.UniformResourceIdentifier(
                                "http://ca.trisoft.com.pl/cacert"
                            ),
                        ),
                        x509.AccessDescription(
                            x509.OID_OCSP,
                            x509.UniformResourceIdentifier(
                                "http://ca.trisoft.com.pl/ocsp"
                            ),
                        ),
                    ]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(names),
                critical=False,
            )
            # certificate_policies
            .add_extension(
                x509.ExtendedKeyUsage(
                    [x509.OID_CLIENT_AUTH, x509.OID_EMAIL_PROTECTION]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=True,  # nonRepudiation
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=True,
                    encipher_only=False,
                    decipher_only=False,
                    # ca
                    key_cert_sign=False,
                    crl_sign=False,
                ),
                critical=True,
            )
            .sign(
                private_key=self.ca_pk,
                algorithm=hashes.SHA256(),
                backend=default_backend(),
            )
        )

    def pk12_save(
        self,
        name: bytes,
        cert: x509.Certificate,
        key: rsa.RSAPrivateKey,
        fname: str,
        password: str,
    ) -> None:
        data = pkcs12.serialize_key_and_certificates(
            name=name,
            key=key,
            cert=cert,
            cas=[self.ca_cert],
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode("utf8")
            ),
        )
        with open(os.path.join("ca", fname), "wb") as f:
            f.write(data)

    def pk12_load(self, fname: str, password: str) -> pkcs12.PKCS12KeyAndCertificates:
        with open(os.path.join("ca", fname), "rb") as fp:
            return pkcs12.load_key_and_certificates(
                fp.read(), password.encode("utf-8"), default_backend()
            )

    def ca_create(self, key: rsa.RSAPrivateKey) -> x509.Certificate:
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "CA"),
            ]
        )
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                # Our certificate will be valid for 10 years
                datetime.datetime.utcnow()
                + datetime.timedelta(days=10 * 365)
            )
            .add_extension(
                x509.BasicConstraints(
                    ca=True,
                    path_length=None,  # pathlen: is equal to the number of CAs/ICAs it can sign
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
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
            .sign(
                # Sign our certificate with our private key
                key,
                hashes.SHA256(),
                default_backend(),
            )
        )

    def CA(self) -> None:
        create = force or not (
            os.path.exists(os.path.join("ca", ca))
            and os.path.exists(os.path.join("ca", ca_key))
        )
        if create:
            for fqname in glob.glob("ca/*"):
                os.unlink(fqname)
            print("CA generating certificate")
            ca_pk = self.key_create()
            ca_cert = self.ca_create(ca_pk)

            self.key_save(ca_key, ca_pk, "1234")
            self.cert_save(ca, ca_cert)
        else:
            print("CA using certificate")
            ca_pk = self.key_load(ca_key, "1234")
            ca_cert = self.cert_load(ca)

        self.ca_cert = ca_cert
        self.ca_pk = ca_pk

    def USER(self, no, cert, cert_key, cert_pub, cert_p12) -> None:
        create = force or not (
            os.path.exists(os.path.join("ca", cert))
            and os.path.exists(os.path.join("ca", cert_key))
            and os.path.exists(os.path.join("ca", cert_pub))
            and os.path.exists(os.path.join("ca", cert_p12))
        )
        if create:
            client_pk = self.key_create()
            client_csr = self.csr_create("demo%d@trisoft.com.pl" % no, client_pk)
            client_cert = self.csr_sign(client_csr)
            self.cert_save(cert, client_cert)
            self.key_save(cert_key, client_pk, "1234")
            self.key_save(cert_pub, client_pk, None)
            self.pk12_save(
                "USER cert".encode("utf-8"), client_cert, client_pk, cert_p12, "1234"
            )

            # os.chmod(pkcs12 % user, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 perms

    def USERs(self):
        self.USER(1, cert1, cert1_key, cert1_pub, cert1_p12)
        self.USER(2, cert2, cert2_key, cert2_pub, cert2_p12)


print("Generating certificates")
cls = Main()
cls.CA()
cls.USERs()
