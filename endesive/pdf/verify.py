# *-* coding: utf-8 *-*
import os
import sys
import glob
import logging
import hashlib

from asn1crypto import x509, core, pem, cms, tsp, crl, ocsp, pdf
from certvalidator import CertificateValidator, ValidationContext

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend

from endesive import verifier


logger = logging.getLogger(__name__)


class PDFVerifier:
    def __init__(self, pdf_data: bytes, trustedCerts=None, systemCertsPath=None):
        self.pdf_data = pdf_data
        self.modified = False
        self.wholefile = False
        self.byte_ranges = []
        certs = None
        if trustedCerts is not None:
            certs = []
            for cert_bytes in trustedCerts:
                # cert_bytes = cert_bytes.encode("utf8")
                if pem.detect(cert_bytes):
                    _, _, cert_bytes = pem.unarmor(cert_bytes)
                certs.append(x509.Certificate.load(cert_bytes))
        if systemCertsPath is not None:
            if not certs:
                certs = []
            for fname in glob.glob(os.path.join(systemCertsPath, "*.pem")):
                with open(fname, "rb") as fp:
                    cert_bytes = fp.read()
                if pem.detect(cert_bytes):
                    _, _, cert_bytes = pem.unarmor(cert_bytes)
                certs.append(x509.Certificate.load(cert_bytes))
        self.context = ValidationContext(certs)

    def validate_certificate(self, cert, othercerts=[]) -> bool:
        validator = CertificateValidator(
            cert, othercerts, validation_context=self.context
        )
        try:
            path = validator.validate_usage(set(["digital_signature"]))
            certok = True
        except Exception as ex:
            logger.exception(ex)
            certok = False
        return certok

    def is_valid_pdf(self) -> bool:
        return b"%PDF-" in self.pdf_data[:1024]

    def is_signed(self) -> bool:
        n = 0
        while True:
            n = self.pdf_data.find(b"/ByteRange", n)
            if n == -1:
                break
            start = self.pdf_data.find(b"[", n)
            stop = self.pdf_data.find(b"]", start)
            if start == -1 or stop == -1:
                self.modified = True
                return False
            n = stop + 1
            try:
                br = [int(i, 10) for i in self.pdf_data[start + 1 : stop].split()]
                assert self.pdf_data[br[1]] == 60 and self.pdf_data[br[2]-1] == 62
            except:
                self.modified = True
                return False
            self.byte_ranges.append(br)

        if len(self.byte_ranges) == 0:
            return False

        byte_range = self.byte_ranges[-1] # last signature
        if byte_range[0]!=0 or byte_range[2]+byte_range[3] != len(self.pdf_data):
            self.wholefile = False
            return False
        self.wholefile = True

        return True

    def decompose_signed_data(self, datau: bytes, signed_data: cms.SignedData) -> tuple:
        signature = signed_data["signer_infos"][0]["signature"].native
        algo = signed_data["digest_algorithms"][0]["algorithm"].native
        attrs = signed_data["signer_infos"][0]["signed_attrs"]
        mdData = getattr(hashlib, algo)(datau).digest()
        if attrs is not None and not isinstance(attrs, core.Void):
            mdSigned = None
            for attr in attrs:
                if attr["type"].native == "message_digest":
                    mdSigned = attr["values"].native[0]
            signedData = attrs.dump()
            signedData = b"\x31" + signedData[1:]
        else:
            mdSigned = mdData
            signedData = datau
        hashok = mdData == mdSigned
        cert = None
        othercerts = []
        serial = signed_data["signer_infos"][0]["sid"].native["serial_number"]
        for pdfcert in signed_data["certificates"]:
            if serial != pdfcert.native["tbs_certificate"]["serial_number"]:
                othercerts.append(pdfcert.chosen)
            else:
                cert = pdfcert.chosen
        public_key = cx509.load_pem_x509_certificate(
            pem.armor("CERTIFICATE", cert.dump()), default_backend()
        ).public_key()

        sigalgo = signed_data["signer_infos"][0]["signature_algorithm"]
        sigalgoname = sigalgo.signature_algo
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            try:
                public_key.verify(
                    signature,
                    signedData,
                    ec.ECDSA(getattr(hashes, algo.upper())()),
                )
                signatureok = True
            except Exception as e:
                signatureok = False
        elif sigalgoname == "rsassa_pss":
            parameters = sigalgo["parameters"]
            # parameters.debug()
            # print(parameters.native)
            salgo = parameters["hash_algorithm"].native["algorithm"].upper()
            mgf = getattr(
                padding, parameters["mask_gen_algorithm"].native["algorithm"].upper()
            )(getattr(hashes, salgo)())
            salt_length = parameters["salt_length"].native
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PSS(mgf, salt_length),
                    getattr(hashes, salgo)(),
                )
                signatureok = True
            except:
                signatureok = False
        elif sigalgoname == "rsassa_pkcs1v15":
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PKCS1v15(),
                    getattr(hashes, algo.upper())(),
                )
                signatureok = True
            except:
                signatureok = False
        else:
            raise ValueError("Unknown signature algorithm")

        tspdata = None
        for attr in signed_data["signer_infos"][0]["unsigned_attrs"]:
            if attr["type"].native == "signature_time_stamp_token":
                for v in attr["values"]:
                    if v["content_type"].native == "signed_data":
                        tspdata = v["content"]
        crls = signed_data["crls"]

        return (signed_data, tspdata, crls, cert, othercerts, hashok, signatureok)

    def decompose_signature(self) -> tuple:
        byte_range = self.byte_ranges[-1] # last signature
        contents = self.pdf_data[byte_range[0] + byte_range[1] + 1 : byte_range[2] - 1]
        try:
            signaturebytes = bytes.fromhex(contents.decode("utf8"))
        except:
            return False
        data1 = self.pdf_data[byte_range[0] : byte_range[0] + byte_range[1]]
        data2 = self.pdf_data[byte_range[2] : byte_range[2] + byte_range[3]]
        datau = data1 + data2

        signed_data = cms.ContentInfo.load(signaturebytes)["content"]
        return self.decompose_signed_data(datau, signed_data)

    def verify_ocsp_data(self, cert, othercerts, crldata):
        for crl1 in crldata:
            # clr1: cms.RevocationInfoChoice
            if crl1.native["other_rev_info_format"] != "ocsp_response":
                logger.debug("bad ocsp data")
                return False, None
            elif crl1.native["other_rev_info"]["response_status"] != "successful":
                logger.debug(f"ocsp response status failure: {crl1.native['other_rev_info']['response_status']}")
                return False, None
            elif crl1.native["other_rev_info"]["response_bytes"]["response_type"] == "basic_ocsp_response":
                crlresp : ocsp.BasicOCSPResponse = crl1.chosen[1][1][1].parsed
                #crlresp = crl1.native["other_rev_info"]["response_bytes"]["response"]
                produced_at = crlresp["tbs_response_data"]["produced_at"].native
                cert_was_checked = False
                next_check_at = None
                for ccert in crlresp["tbs_response_data"]["responses"]:
                    v = ccert["cert_id"]["serial_number"].native == cert.serial_number
                    if v:
                        cert_was_checked = True
                        next_check_at = ccert["next_update"].native
                        break
                sigalgo = crlresp["signature_algorithm"]["algorithm"].native
                sig = crlresp["signature"].native
                sigok = False
                ocspcert = None
                for othercert in crlresp["certs"]:
                    for ext in othercert["tbs_certificate"]["extensions"]:
                        if ext["extn_id"].native == "extended_key_usage" and "ocsp_signing" in ext["extn_value"].native:
                            ocspcert = othercert
                if ocspcert:
                    bcert = x509.Certificate.load(ocspcert.dump())
                    if self.validate_certificate(bcert, othercerts) and not sigok:
                        try:
                            public_key = cx509.load_pem_x509_certificate(
                                pem.armor("CERTIFICATE", ocspcert.dump()), default_backend()
                            ).public_key()
                            signedData = crlresp["tbs_response_data"].dump()
                            # only sha256_rsa
                            public_key.verify(
                                sig,
                                signedData,
                                padding.PKCS1v15(),
                                getattr(hashes, "SHA256")(),
                            )
                            sigok = True
                        except:
                            logger.debug(f"ocsp signing certificate is invalid")
                            pass
                if sigok and cert_was_checked:
                    return True, (produced_at, next_check_at)
                logger.debug(f"ocsp cannot be verified")
            else:
                logger.debug(f"ocsp unknown response type: {crl1.native['other_rev_info']['response_bytes']['response_type']}")
        return False, None

    def verify_tsp_data(self, signed_data, tspdata, othercerts):
        if tspdata['encap_content_info']['content_type'].native == 'tst_info':
            (_, _, tcrldata, tcert, tothercerts, _, tsignatureok) = self.decompose_signed_data(b'', tspdata)
            if tsignatureok and self.validate_certificate(tcert, othercerts):
                tst = tspdata['encap_content_info']['content'].parsed
                signature_bytes = signed_data['signer_infos'][0]['signature'].native
                md = hashlib.sha256(signature_bytes).digest()
                if md == tst['message_imprint']['hashed_message'].native:
                    return True, tst['gen_time'].native
        return False, None


def verify(pdfdata, certs=None, systemCertsPath=None):
    results = []
    n = pdfdata.find(b"/ByteRange")
    while n != -1:
        start = pdfdata.find(b"[", n)
        stop = pdfdata.find(b"]", start)
        assert n != -1 and start != -1 and stop != -1
        br = [int(i, 10) for i in pdfdata[start + 1 : stop].split()]
        assert pdfdata[br[1]] == 60 and pdfdata[br[2]-1] == 62
        contents = pdfdata[br[0] + br[1] + 1 : br[2] - 1]
        bcontents = bytes.fromhex(contents.decode("utf8"))
        data1 = pdfdata[br[0] : br[0] + br[1]]
        data2 = pdfdata[br[2] : br[2] + br[3]]
        signedData = data1 + data2

        result = verifier.verify(bcontents, signedData, certs, systemCertsPath)
        results.append(result)
        n = pdfdata.find(b"/ByteRange", br[2] + br[3])
    return results
