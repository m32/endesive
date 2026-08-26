from __future__ import annotations

import base64
import hashlib

import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from paramiko import SSHException, agent, message

from endesive.exceptions import HSMError


class BaseHSM:
    """Base interface for hardware-backed signing backends."""

    def certificate(self) -> tuple[str, bytes]:
        """Return the certificate fingerprint and certificate bytes for the active key.

        Args:
            None.

        Returns:
            A tuple of ``(fingerprint, certificate_pem)``.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError

    def sign(self, keyid: str, data: bytes, mech: str) -> bytes:
        """Sign data with the selected HSM key.

        Args:
            keyid: Key identifier returned by :meth:`certificate`.
            data: Data to sign.
            mech: Hashing algorithm name.

        Returns:
            PKCS#7 signature bytes.

        Raises:
            NotImplementedError: Subclasses must implement this method.
        """
        raise NotImplementedError


class HSM(BaseHSM):
    def __init__(self, dllpath: str) -> None:
        """Initialize the PyKCS#11-backed HSM connection.

        Args:
            dllpath: Path to the PKCS#11 library.
        """
        self.pkcs11: PyKCS11.PyKCS11Lib = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(dllpath)
        self.session: PyKCS11.Session | None = None

    def getSlot(self, label: str) -> int | None:
        """Return the HSM slot index matching the given label.

        Args:
            label: Token label to look up.

        Returns:
            The matching slot number or ``None`` if not found.
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

    def create(self, label: str, pin: str, sopin: str) -> None:
        """Create a new token and initialize its user PIN.

        Args:
            label: Token label.
            pin: User PIN to set.
            sopin: Security officer PIN.
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

    def login(self, label: str, pin: str) -> None:
        """Open a session for the token identified by label.

        Args:
            label: Token label.
            pin: User PIN.
        """
        slot = self.getSlot(label)
        if slot is None:
            return
        self.session = self.pkcs11.openSession(
            slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION
        )
        self.session.login(pin)

    def logout(self) -> None:
        """Close the active PKCS#11 session if it exists."""
        if self.session is not None:
            self.session.logout()
            self.session.closeSession()
            self.session = None

    def gen_privkey(self, label: str, key_id: bytes, key_length: int = 2048) -> None:
        """Generate a private/public key pair inside the HSM token.

        Args:
            label: Key label.
            key_id: Identifier used to match the key pair.
            key_length: Key size in bits.
        """
        # label - just a label for identifying objects
        # key_id has to be the same for both objects, it will also be necessary
        #     when importing the certificate, to ensure it is linked with these keys.
        # key_length - key-length in bits

        if self.session is None:
            raise HSMError("Session is not initialized. Call login() first.")

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
            (PyKCS11.CKA_ID, key_id),
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
            (PyKCS11.CKA_ID, key_id),
            #            (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
        ]

        self.session.generateKeyPair(public_template, private_template)

    def cert_save(self, cert, label, subject, key_id):
        """Store a certificate object inside the HSM token.

        Args:
            cert: DER-encoded certificate payload.
            label: Certificate label.
            subject: Certificate subject string.
            key_id: Key identifier associated with the certificate.
        """
        if self.session is None:
            raise HSMError("Session is not initialized. Call login() first.")

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
        """Load certificate bytes for the supplied key identifier.

        Args:
            keyID: Key identifier to search for.

        Returns:
            Certificate bytes or ``None`` when no matching certificate exists.
        """
        if self.session is None:
            raise HSMError("Session is not initialized. Call login() first.")

        rec = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_ID, keyID)]
        )
        if len(rec) == 0:
            return None
        value = bytes(rec[0].to_dict()["CKA_VALUE"])
        return value


class SSHAgentHSM(BaseHSM):
    def __init__(self, cert):
        if not isinstance(cert, x509.Certificate):
            raise HSMError("cert must be an x509.Certificate instance")
        self._a = agent.Agent()
        self._cert = cert

    def close(self):
        self._a.close()

    def certificate(self):
        """Return the SSH agent key fingerprint and PEM certificate for the active key.

        Returns:
            A tuple of ``(fingerprint, certificate_pem)``.
        """

        # https://superuser.com/questions/421997/what-is-a-ssh-key-fingerprint-and-how-is-it-generated
        # convert RSA Key to SSH Fingerprint
        alg, key = (
            self._cert.public_key()
            .public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
            .split(b" ")
        )

        fp = b"SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(key)).digest()
        )
        cert = self._cert.public_bytes(serialization.Encoding.PEM)

        return fp, cert

    @staticmethod
    def _decode_fp(keyfp):
        """Decode an OpenSSH fingerprint string into its algorithm and raw bytes.

        Args:
            keyfp: Fingerprint in OpenSSH format, for example ``SHA256:...``.

        Returns:
            A tuple of ``(algorithm_name, fingerprint_bytes)``.

        Raises:
            HSMError: If the fingerprint algorithm is unsupported.
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
            raise HSMError(f"Unsupported fingerprint algorithm: {alg}")
        return alg.lower(), fp

    def key(self, fp):
        """Look up a key exported by the SSH agent using a fingerprint.

        Args:
            fp: Fingerprint identifying the key.

        Returns:
            The matching SSH agent key.

        Raises:
            HSMError: If no matching key is found.
        """

        alg, fp = self._decode_fp(fp)
        for key in self._a.get_keys():
            kfp = getattr(hashlib, alg)(key.asbytes()).digest()
            if kfp == fp:
                break
        else:
            raise HSMError("Key not found")
        return key

    def sign(self, keyid, data, hashalgo):
        """Create an SSH-agent signature for the supplied payload.

        Args:
            keyid: Key identifier returned by :meth:`certificate`.
            data: Data to sign.
            hashalgo: Hash algorithm name, one of ``sha1``, ``sha256``, or ``sha512``.

        Returns:
            Raw PKCS#7-style signature bytes.

        Raises:
            HSMError: If the hash algorithm is unsupported or the key cannot be used.
        """
        if hashalgo not in ("sha1", "sha256", "sha512"):
            raise HSMError(
                f"Unsupported hash algorithm for SSH signing: {hashalgo}. "
                "Expected sha1, sha256 or sha512"
            )

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
        msg = message.Message()
        msg.add_byte(agent.cSSH2_AGENTC_SIGN_REQUEST)
        msg.add_string(key.blob)
        msg.add_string(data)
        msg.add_int(flags)
        ptype, result = self._a._send_message(msg)
        if ptype != agent.SSH2_AGENT_SIGN_RESPONSE:
            raise SSHException("key cannot be used for signing")
        d = message.Message(result.get_binary())

        # parse operation result
        alg = d.get_text()

        # interpret
        if alg in ("ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"):
            sig = d.get_binary()
        else:
            raise HSMError(f"Unsupported SSH signing algorithm: {alg}")
        return sig
