"""Custom exception hierarchy for the endesive library."""


class EndesiveError(ValueError):
    """Base class for library-specific errors."""


class SignerError(EndesiveError):
    """Raised when signing configuration or content is invalid."""


class HashAlgorithmError(EndesiveError):
    """Raised when an unsupported or invalid hash algorithm is used."""


class TimestampError(EndesiveError):
    """Raised when timestamping fails or the response is invalid."""


class DecryptionError(EndesiveError):
    """Raised when encrypted content cannot be parsed or decrypted."""


class EncryptionError(EndesiveError):
    """Raised when message encryption parameters are invalid."""


class EmailVerificationError(EndesiveError):
    """Raised when an S/MIME email is invalid or not signed."""


class SignatureVerificationError(EndesiveError):
    """Raised when a digital signature is invalid or unverifiable."""


class HSMError(EndesiveError):
    """Raised when an HSM operation fails."""


class OCSPVerificationError(EndesiveError):
    """Raised when OCSP validation fails."""


class TSPVerificationError(EndesiveError):
    """Raised when TSP validation fails."""


__all__ = [
    "EndesiveError",
    "SignerError",
    "HashAlgorithmError",
    "TimestampError",
    "DecryptionError",
    "EncryptionError",
    "EmailVerificationError",
    "SignatureVerificationError",
    "HSMError",
    "OCSPVerificationError",
    "TSPVerificationError",
]
