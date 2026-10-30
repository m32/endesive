import unittest
from unittest import mock

from fake_tsa import FakeTSA
from test_cert import CA, ca_root_cert, cert1_p12, fixture

from endesive import pdf, signer, verifier
from endesive.pdf.verify import PDFVerifier

TSPURL = "http://tsa.example/tsp"


class TSPTests(unittest.TestCase):
    def setUp(self):
        self.p12 = CA().pk12_load(cert1_p12, "1234")
        with open(ca_root_cert, "rb") as fh:
            self.ca_root_pem = fh.read()

    def _sign_and_verify(self, tsa, hashalgo, datau=b"timestamped data"):
        with mock.patch("requests.post", side_effect=tsa.post):
            datas = signer.sign(
                datau,
                self.p12[0],
                self.p12[1],
                self.p12[2],
                hashalgo,
                tspurl=TSPURL,
            )
        return verifier.verify(datas, datau, [self.ca_root_pem, tsa.root_pem])

    def test_signature_timestamp_with_each_hash_algorithm(self):
        for hashalgo in ("sha256", "sha384", "sha512"):
            with self.subTest(hashalgo):
                tsa = FakeTSA()
                result = self._sign_and_verify(tsa, hashalgo)
                self.assertEqual(
                    tsa.requests[0]["message_imprint"]["hash_algorithm"]["algorithm"].native,
                    hashalgo,
                )
                self.assertTrue(result.hashok and result.signatureok and result.certok)
                self.assertIs(result.tspok, True, result.tspmsg)
                self.assertIsNotNone(result.tspdata)

    def test_signature_timestamp_with_wrong_imprint_is_rejected(self):
        result = self._sign_and_verify(FakeTSA(tamper_imprint=True), "sha512")
        self.assertIs(result.tspok, False)
        self.assertEqual(result.tspmsg, "Invalid hash value")

    def _timestamp_pdf(self, tsa):
        with open(fixture("pdf.pdf"), "rb") as fh:
            datau = fh.read()
        with mock.patch("requests.post", side_effect=tsa.post):
            datas = pdf.cms.timestamp(
                datau, {"signingdate": "20260101000000+00'00'"}, "sha256", TSPURL
            )
        return datau + datas

    def test_pdf_document_timestamp(self):
        tsa = FakeTSA()
        result, _ = pdf.verify(self._timestamp_pdf(tsa), [tsa.root_pem])
        self.assertIsNone(result.signed_data)
        self.assertIs(result.tspok, True, result.tspmsg)

    def test_pdf_document_timestamp_detects_modified_document(self):
        tsa = FakeTSA()
        data = bytearray(self._timestamp_pdf(tsa))
        self.assertEqual(data[:8], b"%PDF-1.3")
        data[7:8] = b"4"
        result, _ = pdf.verify(bytes(data), [tsa.root_pem])
        self.assertIs(result.tspok, False)
        self.assertEqual(result.tspmsg, "Invalid hash value")

    def test_document_timestamp_without_data_is_not_valid(self):
        tsa = FakeTSA()
        verifier_ = PDFVerifier(self._timestamp_pdf(tsa), [tsa.root_pem])
        result = verifier_.verify_signature(0)
        verifier_.verify_tsp_data(result)
        self.assertIs(result.tspok, False)


if __name__ == "__main__":
    unittest.main()
