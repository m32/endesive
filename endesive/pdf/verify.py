from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes

from endesive import verifier

if TYPE_CHECKING:
    from asn1crypto import x509

logger = logging.getLogger(__name__)


_SIG_HASH_ALGOS = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class RemainingData(object):
    def __init__(self, start, stop):
        self.start = start
        self.stop = stop


class PDFVerifier(verifier.SignatureVerifier):
    """
    PDF signature verifier.
        :param pdf_data: PDF document as bytes.
        :param trusted_certs: List of system independent trusted certificates used to verify certificates.
    """

    def __init__(
        self,
        pdf_data: bytes,
        trusted_certs: list[bytes | x509.Certificate] | None = None,
    ):
        super().__init__(trusted_certs)
        self.pdf_data = pdf_data
        self.byte_ranges: list[tuple[int, int, int, int]] = []
        self._find_byte_ranges()

    @property
    def is_valid_pdf(self) -> bool:
        return b"%PDF-" in self.pdf_data[:1024]

    @property
    def is_signed(self) -> bool:
        return len(self.byte_ranges) > 0

    @property
    def whole_file(self) -> bool | None:
        if not self.is_signed:
            return None
        byte_range = self.byte_ranges[-1]  # last signature
        return byte_range[0] == 0 and byte_range[2] + byte_range[3] == len(
            self.pdf_data
        )

    def _find_byte_ranges(self):
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
                br = tuple(int(i, 10) for i in self.pdf_data[start + 1 : stop].split())
            except Exception as exc:
                raise ValueError("Invalid ByteRange data") from exc
            if (
                len(br) != 4
                or self.pdf_data[br[1]] != 60
                or self.pdf_data[br[2] - 1] != 62
            ):
                raise ValueError("Invalid ByteRange markers")
            if br[2] + br[3] < stop + 1:
                raise ValueError("Invalid ByteRange data")
            else:
                n = br[2] + br[3]
            self.byte_ranges.append(br)

    def verify_signature(self, no) -> verifier.Result:
        byte_range = self.byte_ranges[no]
        contents = self.pdf_data[byte_range[0] + byte_range[1] + 1 : byte_range[2] - 1]
        try:
            signaturebytes = bytes.fromhex(contents.decode("utf8"))
        except Exception as exc:
            raise ValueError("Invalid signature bytes") from exc
        data1 = self.pdf_data[byte_range[0] : byte_range[0] + byte_range[1]]
        data2 = self.pdf_data[byte_range[2] : byte_range[2] + byte_range[3]]
        datau = data1 + data2

        result = self.decompose_signed_data(signaturebytes, datau)
        if (
            result.signed_data["encap_content_info"]["content_type"].native
            == "tst_info"
        ):
            # timestamped document without signed data
            result.tsp_data = result.signed_data
            result.signed_data = None
            result.crldata = None
            result.cert = None
            result.othercerts = None
            result.hashok = None
            result.signatureok = None
            self.verify_tsp_data(result)
        else:
            result.certok = self.validate_certificate(result.cert, result.othercerts)
            self.verify_ocsp_data(result)
            self.verify_tsp_data(result)

        return result

    def verify_all_signatures(self) -> list[verifier.Result]:
        results = []
        for no in range(len(self.byte_ranges)):
            result = self.verify_signature(no)
            results.append(result)
        return results

    def get_remaining_data(self) -> RemainingData | None:
        if self.whole_file:
            return None
        byte_range = self.byte_ranges[-1]  # last signature
        if byte_range[0] != 0:
            raise ValueError("Invalid ByteRange data")
        return RemainingData(byte_range[2] + byte_range[3], len(self.pdf_data))

    def verify(self) -> tuple[verifier.Result, RemainingData | None]:
        """
        Verify PDF signatures.

        :return:
            tuple[verifier.Result, RemainingData | None]: A tuple containing the result of the signature verification and the remaining data (if any).

        :raises ValueError: If the PDF is invalid or unsigned.
        """

        if not self.is_valid_pdf:
            raise ValueError("Invalid PDF")
        if not self.is_signed:
            raise ValueError("Unsigned PDF")
        vls = self.verify_signature(len(self.byte_ranges) - 1)
        vrd = self.get_remaining_data()
        return vls, vrd


def verify(
    pdfdata: bytes, certs: list[bytes | x509.Certificate] | None = None
) -> tuple[verifier.Result, RemainingData | None]:
    cls = PDFVerifier(pdfdata, certs)
    return cls.verify()
