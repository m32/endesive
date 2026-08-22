# *-* coding: utf-8 *-*
import logging
import hashlib
import datetime
import warnings

import certifi

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509 import verification, extensions
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend

from endesive import verifier


logger = logging.getLogger(__name__)


_SIG_HASH_ALGOS = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class PDFVerifier(verifier.SignatureVerifier):
    """
    PDF signature verifier.
        :param pdf_data: PDF document as bytes.
        :param trusted_certs: List of system independent trusted certificates used to verify certificates.
    """
    def __init__(self, pdf_data: bytes, trusted_certs:list[bytes]|None=None):
        super().__init__(trusted_certs)
        self.pdf_data = pdf_data
        self.modified = False
        self.wholefile = False
        self.byte_ranges = []

    def _is_valid_pdf(self) -> bool:
        return b"%PDF-" in self.pdf_data[:1024]

    def _is_signed(self) -> bool:
        n = 0
        while True:
            n = self.pdf_data.find(b"/ByteRange", n)
            if n == -1:
                break
            start = self.pdf_data.find(b"[", n)
            stop = self.pdf_data.find(b"]", start)
            if start == -1 or stop == -1:
                raise ValueError("Invalid ByteRange data")
            try:
                br = [int(i, 10) for i in self.pdf_data[start + 1 : stop].split()]
            except Exception as exc:
                raise ValueError("Invalid ByteRange data") from exc
            if len(br) != 4 or self.pdf_data[br[1]] != 60 or self.pdf_data[br[2] - 1] != 62:
                raise ValueError("Invalid ByteRange markers")
            if br[2]+br[3] < stop + 1:
                raise ValueError("Invalid ByteRange data")
            else:
                n = br[2] + br[3]
            self.byte_ranges.append(br)

        if len(self.byte_ranges) == 0:
            return False

        byte_range = self.byte_ranges[-1] # last signature
        if byte_range[0]!=0 or byte_range[2]+byte_range[3] != len(self.pdf_data):
            self.wholefile = False
            return False
        self.wholefile = True

        return True

    def _decompose_signature(self, byte_range) -> tuple:
        contents = self.pdf_data[byte_range[0] + byte_range[1] + 1 : byte_range[2] - 1]
        try:
            signaturebytes = bytes.fromhex(contents.decode("utf8"))
        except Exception as exc:
            raise ValueError("Invalid signature bytes") from exc
        data1 = self.pdf_data[byte_range[0] : byte_range[0] + byte_range[1]]
        data2 = self.pdf_data[byte_range[2] : byte_range[2] + byte_range[3]]
        datau = data1 + data2

        return self.decompose_signed_data(signaturebytes, datau)

    def verify(self) -> list[tuple[bool, bool, bool, bool|None, list[datetime.datetime]|None, bool|None, datetime.datetime|None]]:
        """
        Verify PDF signature.

        :param pdfdata: PDF document as bytes.
        :param certs: Optional list of system independent trusted certificates used to verify signature.

        :return:
            list[hashok, signatureok, certok, ocspok, ocspdata, tspok, tspdata]

            hashok: bool
                True if hash is matches, False otherwise.
            signatureok: bool
                True if signature is valid, False otherwise.
            certok: bool
                True if certificate is valid, False otherwise.
            ocspok: bool|None
                True if OCSP is valid, False if invalid, None if not present.
            ocspdata: list[datetime.datetime]|None
                List of OCSP produced_at and next_check_at datetimes,
                or None if not present.
            tspok: bool|None
                True if TSP is valid, False if invalid, None if not present.
            tspdata: datetime.datetime|None
                TSP produced_at datetime, or None if not present."""
        if not self._is_valid_pdf():
            raise ValueError("Invalid PDF")
        if not self._is_signed():
            if self.modified:
                raise ValueError("Modified PDF")
            if not self.wholefile:
                raise ValueError("Partially signed PDF")
            raise ValueError("Unsigned PDF")

        results = []
        for byte_range in self.byte_ranges:
            (signed_data, tsp_data, crldata, cert, othercerts, hashok, signatureok) = self._decompose_signature(byte_range)
            certok = self.validate_certificate(cert, othercerts)
            ocspok, ocspdata = None, None
            if crldata.native is not None:
                ocspok, ocspdata = self.verify_ocsp_data(cert, othercerts, crldata)
            tspok, tspdata = None, None
            if tsp_data is not None:
                tspok, tspdata = self.verify_tsp_data(signed_data, tsp_data)

            results.append((hashok, signatureok, certok, ocspok, ocspdata, tspok, tspdata))
        return results

def verify(
    pdfdata:bytes,
    certs:list[bytes]|None=None
) -> list[tuple[bool, bool, bool, bool|None, list[datetime.datetime]|None, bool|None, datetime.datetime|None]]:
    """
    Deprecated shortcut to PDFVerifier.verify
    """
    cls = PDFVerifier(pdfdata, certs)
    return cls.verify()

