import io
import unittest
from types import SimpleNamespace
from unittest import mock

import pypdf
import requests
from fake_tsa import FakeTSA
from test_cert import CA, ca_root_cert, cert1_p12, fixture

from endesive import pdf, signer, verifier
from endesive.exceptions import TimestampError
from endesive.pdf.verify import PDFVerifier
from endesive.xades import BES

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
        # as for a signature made without checking the reply
        with mock.patch("endesive.signer.check_tsp_reply"):
            result = self._sign_and_verify(FakeTSA(tamper_imprint=True), "sha512")
        self.assertIs(result.tspok, False)
        self.assertEqual(result.tspmsg, "Invalid hash value")

    def test_reply_for_another_request_is_rejected(self):
        cases = {
            "imprint": (FakeTSA(tamper_imprint=True), "another message imprint"),
            "nonce": (FakeTSA(wrong_nonce=True), "nonce does not match"),
        }
        for label, (tsa, message) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(TimestampError, message):
                    self._sign_and_verify(tsa, "sha256")
                with self.assertRaisesRegex(TimestampError, message):
                    self._timestamp_pdf(tsa)
                with mock.patch("requests.post", side_effect=tsa.post):
                    with self.assertRaisesRegex(TimestampError, message):
                        BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, None)

    def test_unparsable_reply_is_rejected(self):
        reply = SimpleNamespace(
            status_code=200,
            headers={"Content-Type": "application/timestamp-reply"},
            content=b"not a time-stamp response",
        )
        with mock.patch("requests.post", return_value=reply):
            with self.assertRaisesRegex(TimestampError, "Invalid timestamp server response"):
                signer.fetch_tsp_response(b"data", "sha256", TSPURL, None)

    def test_signature_timestamp_with_swapped_tst_info_is_rejected(self):
        result = self._sign_and_verify(FakeTSA(swap_tst_info=True), "sha256")
        self.assertIs(result.tspok, False)
        self.assertEqual(result.tspmsg, "TSP message digest is invalid")

    def test_pdf_document_timestamp_with_swapped_tst_info_is_rejected(self):
        tsa = FakeTSA(swap_tst_info=True)
        result, _ = pdf.verify(self._timestamp_pdf(tsa), [tsa.root_pem])
        self.assertIs(result.tspok, False)
        self.assertEqual(result.tspmsg, "TSP message digest is invalid")

    def test_signature_fails_when_timestamp_server_does_not_answer(self):
        responses = {
            "connection error": mock.Mock(side_effect=requests.ConnectionError("down")),
            "http error": mock.Mock(
                return_value=SimpleNamespace(status_code=500, headers={}, content=b"")
            ),
        }
        for label, post in responses.items():
            with self.subTest(label), mock.patch("requests.post", post):
                with self.assertRaisesRegex(TimestampError, "No response"):
                    signer.sign(
                        b"data", self.p12[0], self.p12[1], self.p12[2], "sha256",
                        tspurl=TSPURL,
                    )
                with self.assertRaisesRegex(TimestampError, "No response"):
                    BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, None)
                with self.assertRaisesRegex(TimestampError, "No response"):
                    pdf.cms.sign(
                        self._pdf(), {"signingdate": "D:20260101000000+00'00'"},
                        self.p12[0], self.p12[1], self.p12[2], "sha256",
                        tspurl=TSPURL,
                    )

    def test_reply_content_type_parameters_and_case_are_ignored(self):
        for content_type in (
            "application/timestamp-reply; charset=binary",
            "Application/Timestamp-Reply",
        ):
            with self.subTest(content_type):
                tsa = FakeTSA(content_type=content_type)
                result = self._sign_and_verify(tsa, "sha256")
                self.assertIs(result.tspok, True, result.tspmsg)

                tsa = FakeTSA(content_type=content_type)
                with mock.patch("requests.post", side_effect=tsa.post):
                    props = BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, None)
                self.assertEqual(len(props.findall(".//{*}EncapsulatedTimeStamp")), 1)

    def test_reply_with_other_content_type_is_rejected(self):
        tsa = FakeTSA(content_type="text/html")
        with self.assertRaisesRegex(TimestampError, "No response"):
            self._sign_and_verify(tsa, "sha256")
        with mock.patch("requests.post", side_effect=tsa.post):
            with self.assertRaisesRegex(TimestampError, "No response"):
                BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, None)

    def test_xades_timestamp_request_options(self):
        tsa = FakeTSA()
        post = mock.Mock(side_effect=tsa.post)
        cred = {"username": "user", "password": "pass", "verify": False}
        with mock.patch("requests.post", post):
            BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, cred)
        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["headers"]["Authorization"], "Basic dXNlcjpwYXNz")
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/timestamp-query")
        self.assertIs(kwargs["verify"], False)
        self.assertEqual(kwargs["timeout"], signer.DEFAULT_HTTP_TIMEOUT)
        self.assertEqual(cred, {"username": "user", "password": "pass", "verify": False})

    def _pdf(self):
        with open(fixture("pdf.pdf"), "rb") as fh:
            return fh.read()

    def _timestamp_pdf(self, tsa, udct=None):
        datau = self._pdf()
        if udct is None:
            udct = {"signingdate": "20260101000000+00'00'"}
        with mock.patch("requests.post", side_effect=tsa.post):
            datas = pdf.cms.timestamp(datau, udct, "sha256", TSPURL)
        return datau + datas

    @staticmethod
    def _doc_timestamp_dict(data):
        reader = pypdf.PdfReader(io.BytesIO(data))
        field = reader.trailer["/Root"]["/AcroForm"]["/Fields"][-1].get_object()
        sig = field["/V"].get_object()
        assert sig["/Type"] == "/DocTimeStamp"
        return sig

    def test_pdf_document_timestamp_without_signingdate(self):
        tsa = FakeTSA()
        data = self._timestamp_pdf(tsa, {})
        self.assertNotIn("/M", self._doc_timestamp_dict(data))
        result, _ = pdf.verify(data, [tsa.root_pem])
        self.assertIs(result.tspok, True, result.tspmsg)

    def test_pdf_document_timestamp_keeps_given_signingdate(self):
        data = self._timestamp_pdf(FakeTSA())
        self.assertEqual(self._doc_timestamp_dict(data)["/M"], "20260101000000+00'00'")

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

    def test_granted_with_mods_is_accepted(self):
        with self.subTest("cms signature"):
            tsa = FakeTSA(status="granted_with_mods")
            result = self._sign_and_verify(tsa, "sha256")
            self.assertIs(result.tspok, True, result.tspmsg)

        with self.subTest("pdf document timestamp"):
            tsa = FakeTSA(status="granted_with_mods")
            result, _ = pdf.verify(self._timestamp_pdf(tsa), [tsa.root_pem])
            self.assertIs(result.tspok, True, result.tspmsg)

        with self.subTest("xades"):
            tsa = FakeTSA(status="granted_with_mods")
            with mock.patch("requests.post", side_effect=tsa.post):
                props = BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, None)
            self.assertEqual(len(tsa.requests), 1)
            self.assertEqual(len(props.findall(".//{*}EncapsulatedTimeStamp")), 1)

    def test_rejected_timestamp_request(self):
        with self.subTest("cms signature"):
            with self.assertRaises(TimestampError):
                self._sign_and_verify(FakeTSA(status="rejection"), "sha256")

        with self.subTest("pdf document timestamp"):
            with self.assertRaises(TimestampError):
                self._timestamp_pdf(FakeTSA(status="rejection"))

        with self.subTest("xades"):
            tsa = FakeTSA(status="rejection")
            with mock.patch("requests.post", side_effect=tsa.post):
                with self.assertRaisesRegex(TimestampError, "not granted"):
                    BES()._unsignedproperties(b"<SignatureValue/>", TSPURL, None)


if __name__ == "__main__":
    unittest.main()
