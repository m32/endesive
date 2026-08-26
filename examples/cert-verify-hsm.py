"""Certificate validation using SoftHSM and certvalidator."""

import datetime

import certifi
import certvalidator
from asn1crypto import pem, x509

from endesive import hsm
from hsm_config_softhsm import DLLPATH


class HSM(hsm.HSM):
    """HSM class for certificate validation using SoftHSM and certvalidator."""

    def load_cert(self, cert_bytes) -> x509.Certificate:
        """Load a certificate from bytes, handling PEM format if necessary."""
        if pem.detect(cert_bytes):
            _, _, cert_bytes = pem.unarmor(cert_bytes)
        return x509.Certificate.load(cert_bytes)

    def get_cert(self, keyid: bytes) -> x509.Certificate:
        """Retrieve a certificate from the HSM using the provided key ID."""
        cert_bytes = self.cert_load(keyid)
        return self.load_cert(cert_bytes)

    def load_trusted_certs(self, trusted_certs=None) -> list[x509.Certificate]:
        """Load trusted certificates from certifi and any additional provided certificates."""
        certs = []
        with open(certifi.where(), "rb") as pems:
            for name, _, data in pem.unarmor(pems.read(), multiple=True):
                if name == "CERTIFICATE":
                    certs.append(self.load_cert(data))
        if trusted_certs is not None:
            for cert_bytes in trusted_certs:
                if isinstance(cert_bytes, x509.Certificate):
                    certs.append(cert_bytes)
                else:
                    certs.append(self.load_cert(cert_bytes))
        return certs

    def validator(
        self,
        cert: x509.Certificate,
        othercerts: list[x509.Certificate] | None = None,
        trustedcerts: list[x509.Certificate] | None = None,
    ) -> certvalidator.CertificateValidator:
        """Create a CertificateValidator for the given certificate,
        with optional intermediate and trusted certificates."""
        validation_context = certvalidator.ValidationContext(
            trust_roots=trustedcerts,
            allow_fetching=False,
            revocation_mode="soft-fail",
            moment=datetime.datetime.now(tz=datetime.timezone.utc),
        )
        validator = certvalidator.CertificateValidator(
            cert,
            intermediate_certs=othercerts,
            validation_context=validation_context,
        )
        return validator

    def main(self):
        """Main method to demonstrate certificate validation using the HSM."""
        caroot = self.get_cert(bytes((0x1,)))
        casub = self.get_cert(bytes((0x2,)))
        user = self.get_cert(
            bytes(
                (
                    0x66,
                    0x66,
                    0x01,
                )
            )
        )

        trustedcerts = self.load_trusted_certs([caroot])

        print("*" * 40, "casub")
        validator = self.validator(casub, trustedcerts=trustedcerts)
        try:
            path = validator.validate_usage(set(["key_cert_sign"]))
        except certvalidator.errors.PathValidationError as e:
            print("Path validation error:", e)
        else:
            print("Validation path:")
            for cert in path:
                print(cert.serial_number, cert.subject.native)

        print("*" * 40, "user")
        validator = self.validator(user, othercerts=[casub], trustedcerts=trustedcerts)
        try:
            path = validator.validate_usage(set(["digital_signature"]))
        except certvalidator.errors.PathValidationError as e:
            print("Path validation error:", e)
        else:
            print("Validation path:")
            for cert in path:
                print(cert.serial_number, cert.subject.native)


def main():
    """Main function to initialize the HSM and perform certificate validation."""
    cls = HSM(DLLPATH)
    cls.login("endesieve", "secret1")
    try:
        cls.main()
    finally:
        cls.logout()


main()
