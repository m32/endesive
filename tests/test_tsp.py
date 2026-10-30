import unittest
from unittest import mock

from fake_tsa import FakeTSA
from test_cert import CA, ca_root_cert, cert1_p12

from endesive import signer, verifier

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


if __name__ == "__main__":
    unittest.main()
