import base64
import hashlib
import unittest
from unittest import mock

from asn1crypto import cms
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from fake_tsa import FakeTSA
from lxml import etree
from test_cert import CA, cert1_p12

from endesive import verifier
from endesive.xades import BES

TSPURL = "http://tsa.example/tsp"
DS = "{http://www.w3.org/2000/09/xmldsig#}"
XADES = "{http://uri.etsi.org/01903/v1.3.2#}"
# a default namespace and a prefixed one, both inherited by ds:SignatureValue
DOCUMENT = b'<doc xmlns="urn:example:doc" xmlns:x="urn:example:x"><x:item>1</x:item></doc>'


class XAdESTimestampTests(unittest.TestCase):
    def setUp(self):
        key, self.cert, _ = CA().pk12_load(cert1_p12, "1234")
        self.certcontent = self.cert.public_bytes(serialization.Encoding.DER)

        def signproc(tosign, algosig):
            return key.sign(tosign, padding.PKCS1v15(), getattr(hashes, algosig.upper())())

        self.signproc = signproc

    def _check_signature_timestamp(self, signed_xml, tsa):
        # parse the serialized output, so the check sees the namespaces a
        # verifier would
        root = etree.fromstring(signed_xml)
        (signaturevalue,) = root.iter(DS + "SignatureValue")
        (stamp,) = root.iter(XADES + "SignatureTimeStamp")
        (c14n_method,) = stamp.iter(DS + "CanonicalizationMethod")
        self.assertEqual(
            c14n_method.get("Algorithm"), "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
        )
        timestamped = etree.tostring(signaturevalue, method="c14n")

        (encapsulated,) = stamp.iter(XADES + "EncapsulatedTimeStamp")
        token = cms.ContentInfo.load(base64.b64decode(encapsulated.text))
        tst = token["content"]["encap_content_info"]["content"].parsed
        self.assertEqual(
            tst["message_imprint"]["hashed_message"].native,
            hashlib.sha256(timestamped).digest(),
        )
        self.assertEqual(len(tsa.requests), 1)

        result = verifier.Result(None, None, None, [], None, None, token["content"])
        verifier.SignatureVerifier([tsa.root_pem]).verify_tsp_data(result, timestamped)
        self.assertIs(result.tspok, True, result.tspmsg)

    def test_enveloped_signature_timestamp_covers_signature_value(self):
        tsa = FakeTSA()
        with mock.patch("requests.post", side_effect=tsa.post):
            tree = BES().enveloped(
                DOCUMENT, self.cert, self.certcontent, self.signproc, TSPURL, None
            )
        self._check_signature_timestamp(etree.tostring(tree), tsa)

    def test_enveloping_signature_timestamp_covers_signature_value(self):
        tsa = FakeTSA()
        with mock.patch("requests.post", side_effect=tsa.post):
            doc = BES().enveloping(
                "document.xml",
                DOCUMENT,
                "application/xml",
                self.cert,
                self.certcontent,
                self.signproc,
                tspurl=TSPURL,
            )
        self._check_signature_timestamp(etree.tostring(doc), tsa)

    def test_without_tspurl_no_timestamp_is_requested(self):
        tsa = FakeTSA()
        with mock.patch("requests.post", side_effect=tsa.post):
            tree = BES().enveloped(
                DOCUMENT, self.cert, self.certcontent, self.signproc, None, None
            )
        self.assertEqual(tsa.requests, [])
        root = tree.getroot()
        self.assertEqual(list(root.iter(XADES + "SignatureTimeStamp")), [])
        self.assertEqual(len(list(root.iter(XADES + "UnsignedProperties"))), 1)


if __name__ == "__main__":
    unittest.main()
