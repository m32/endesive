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

    def verify(self) -> list[tuple[bool, bool, bool]]:
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
            (signed_data, tspdata, crldata, cert, othercerts, hashok, signatureok) = self._decompose_signature(byte_range)
            certok = self.validate_certificate(cert, othercerts)
            if certok and crldata.native is not None:
                ok, info = self.verify_ocsp_data(cert, othercerts, crldata)
                # info = (produced_at, next_check_at)
                if not ok:
                    certok = False
            if certok and tspdata is not None:
                ok, info = self.verify_tsp_data(signed_data, tspdata, othercerts)
                #print('info:', info)
                # info = gen_time
                if not ok:
                    raise ValueError("Invalid TSP")

            results.append((hashok, signatureok, certok))
        return results

def verify(pdfdata:bytes, certs:list[bytes]|None=None) -> list[tuple[bool, bool, bool]]:
    """
    Verify PDF signature.
    :param pdfdata: PDF document as bytes.
    :param certs: List of additional certificates used to verify signature (system independent).
    :return: 
    """
    cls = PDFVerifier(pdfdata, certs)
    return cls.verify()

