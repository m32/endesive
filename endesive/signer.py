# *-* coding: utf-8 *-*
from __future__ import unicode_literals

import sys
import types
import hashlib
import secrets
import requests
from base64 import b64encode
from datetime import datetime
from asn1crypto import cms, algos, core, keys, pem, tsp, x509, ocsp, util
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec
from cryptography.hazmat import backends
from cryptography import x509 as cryptography_x509
from cryptography.x509 import ocsp as cryptography_ocsp


DEFAULT_HTTP_TIMEOUT = 10


def cert2asn(cert, cert_bytes=True):
    if isinstance(cert, x509.Certificate):
        return cert
    if cert_bytes:
        cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    else:
        cert_bytes = cert
    if pem.detect(cert_bytes):
        _, _, cert_bytes = pem.unarmor(cert_bytes)
    return x509.Certificate.load(cert_bytes)

def extract_ocsp_url_from_cert(cert):
    if hasattr(cert, 'public_bytes'):
        crypto_cert = cert
    else:
        if hasattr(cert, 'dump'):
            cert_bytes = cert.dump()
        else:
            cert_bytes = cert
        crypto_cert = cryptography_x509.load_der_x509_certificate(
            cert_bytes, backends.default_backend())
    try:
        aia = crypto_cert.extensions.get_extension_for_oid(
            cryptography_x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access_description in aia.value:
            if access_description.access_method == cryptography_x509.oid.AuthorityInformationAccessOID.OCSP:
                return access_description.access_location.value
    except cryptography_x509.ExtensionNotFound:
        return None
    return None


def fetch_ocsp_response(cert, issuer, url):
    if hasattr(cert, 'dump'):
        cert_bytes = cert.dump()
        cert = cryptography_x509.load_der_x509_certificate(
            cert_bytes, backends.default_backend())
    if hasattr(issuer, 'dump'):
        issuer_bytes = issuer.dump()
        issuer = cryptography_x509.load_der_x509_certificate(
            issuer_bytes, backends.default_backend())
    builder = cryptography_ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA1())
    req = builder.build()
    data = req.public_bytes(serialization.Encoding.DER)
    try:
        response = requests.post(
            url,
            headers={"Content-Type": "application/ocsp-request"},
            data=data,
            timeout=DEFAULT_HTTP_TIMEOUT,
        )
        if response.status_code != 200:
            return None
        return response.content
    except requests.exceptions.RequestException:
        return None


def timestamp(unhashed, hashalgo, url, credentials, req_options, prehashed=None):
    if prehashed:
        hashed_value = prehashed
    else:
        hashed_value = getattr(hashlib, hashalgo)(unhashed).digest()
    tspreq = tsp.TimeStampReq(
        {
            "version": 1,
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": algos.DigestAlgorithm({"algorithm": hashalgo}),
                    "hashed_message": hashed_value,
                }
            ),
            "nonce": secrets.randbits(64),
            "cert_req": True,
        }
    )
    tspreq = tspreq.dump()
    tspheaders = {"Content-Type": "application/timestamp-query"}
    if credentials is not None:
        username = credentials.get("username", None)
        password = credentials.get("password", None)
        if username and password:
            auth_header_value = b64encode(
                bytes(username + ":" + password, "utf-8")
            ).decode("ascii")
            tspheaders["Authorization"] = f"Basic {auth_header_value}"
    if req_options is None:
        req_options = {}
    req_options.setdefault("timeout", DEFAULT_HTTP_TIMEOUT)
    tspresp = requests.post(url, data=tspreq, headers=tspheaders, **req_options)
    if tspresp.headers.get("Content-Type", None) == "application/timestamp-reply":
        tspresp = tsp.TimeStampResp.load(tspresp.content)
        if tspresp["status"]["status"].native == "granted":
            return [
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("signature_time_stamp_token"),
                        "values": cms.SetOfContentInfo(
                            [
                                cms.ContentInfo(
                                    {
                                        "content_type": cms.ContentType("signed_data"),
                                        "content": tspresp["time_stamp_token"]["content"],
                                    }
                                )
                            ]
                        ),
                    }
                )
            ]
        else:
            raise ValueError("TimeStampResponse status is not granted")
    else:
        raise ValueError("TimeStampResponse has invalid content type")


class Signer:
    def __init__(self,
        datau,
        cert,
        othercerts,
        hashalgo,
        attrs=True, #True|False|function
        signed_value=None,
        pss=False,
    ):
        assert attrs is True or attrs is False or isinstance(attrs, types.FunctionType)

        self.datau = datau
        self.cert = cert
        self.othercerts = othercerts
        self.hashalgo = hashalgo.lower()
        self.attrs = attrs
        self.pss = pss
        self.salt_length = None if not pss else self.get_pss_salt_length()

        if signed_value is None:
            signed_value = getattr(hashlib, hashalgo)(datau).digest()

        certificates = []
        certificates.append(cert)
        for certo in othercerts:
            certificates.append(cert2asn(certo))

        self.signed_value = signed_value
        self.certificates = certificates
        self.signed_time = datetime.now(tz=util.timezone.utc)

    def sign(self, tosign):
        return None

    def get_pss_salt_length(self) -> int:
        return 0

    def get_ocsp_response(self, cert):
        return None

    def get_tsp_response(self, signed_value_signature):
        return None

    def build(self):
        signer = {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {
                            "issuer": self.cert.issuer,
                            "serial_number": self.cert.serial_number,
                        }
                    ),
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": self.hashalgo}),
            "signature": self.signed_value,
        }

        if self.pss:
            signer["signature_algorithm"] = algos.SignedDigestAlgorithm(
                {
                    "algorithm": "rsassa_pss",
                    "parameters": algos.RSASSAPSSParams(
                        {
                            "hash_algorithm": algos.DigestAlgorithm(
                                {"algorithm": self.hashalgo.lower()}
                            ),
                            "mask_gen_algorithm": algos.MaskGenAlgorithm(
                                {
                                    "algorithm": algos.MaskGenAlgorithmId("mgf1"),
                                    "parameters": {
                                        "algorithm": algos.DigestAlgorithmId(self.hashalgo.lower()),
                                    },
                                }
                            ),
                            "salt_length": algos.Integer(self.salt_length),
                            "trailer_field": algos.TrailerField(1),
                        }
                    ),
                }
            )
        else:
            signer["signature_algorithm"] = algos.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15"}
            )

        if self.attrs is True:
            signing_certificate1 = cms.CMSAttribute(
                {
                    "type": cms.CMSAttributeType("signing_certificate"),
                    "values": (
                        tsp.SigningCertificate(
                            {
                                "certs": [
                                    tsp.ESSCertID(
                                        {
                                            "cert_hash": hashlib.sha1(
                                                self.cert.dump()
                                            ).digest(),
                                            "issuer_serial": tsp.IssuerSerial(
                                                {
                                                    "issuer": (
                                                        x509.GeneralName(
                                                            {
                                                                "directory_name": self.cert.issuer,
                                                            }
                                                        ),
                                                    ),
                                                    "serial_number": self.cert.serial_number,
                                                }
                                            ),
                                        }
                                    ),
                                ]
                            }
                        ),
                    ),
                }
            )

            signing_certificate2 = cms.CMSAttribute(
                {
                    "type": cms.CMSAttributeType("signing_certificate_v2"),
                    "values": [
                        tsp.SigningCertificateV2(
                            {
                                "certs": [
                                    tsp.ESSCertIDv2(
                                        {
                                            "hash_algorithm": algos.DigestAlgorithm(
                                                {"algorithm": "sha256"}
                                            ),
                                            "cert_hash": hashlib.sha256(
                                                self.cert.dump()
                                            ).digest(),
                                            "issuer_serial": tsp.IssuerSerial(
                                                {
                                                    "issuer": (
                                                        x509.GeneralName(
                                                            {
                                                                "directory_name": self.cert.issuer,
                                                            }
                                                        ),
                                                    ),
                                                    "serial_number": self.cert.serial_number,
                                                }
                                            ),
                                        }
                                    ),
                                ]
                            }
                        ),
                    ],
                }
            )

            signer["signed_attrs"] = [
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("content_type"),
                        "values": ("data",),
                    }
                ),
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("message_digest"),
                        "values": (self.signed_value,),
                    }
                ),
                # cms.CMSAttribute(
                #    {
                #        "type": cms.CMSAttributeType("signing_time"),
                #        "values": (cms.Time({"utc_time": core.UTCTime(signed_time)}),),
                #    }
                # ),
                signing_certificate2,
            ]
        elif isinstance(self.attrs, types.FunctionType):
          signer["signed_attrs"] = self.attrs(self.signed_value)

        config = {
            "version": "v1",
            "digest_algorithms": cms.DigestAlgorithms(
                (algos.DigestAlgorithm({"algorithm": self.hashalgo}),)
            ),
            "encap_content_info": {
                "content_type": "data",
            },
            "certificates": self.certificates,
            "signer_infos": [
                signer,
            ],
        }
        ocsp_response = self.get_ocsp_response(self.cert)
        if ocsp_response:
            other = cms.RevocationInfoChoice(
                {
                    "other": cms.OtherRevocationInfoFormat(
                        {
                            "other_rev_info_format": cms.OtherRevInfoFormatId(
                                "ocsp_response"
                            ),
                            "other_rev_info": ocsp_response,
                        }
                    )
                }
            )
            config["crls"] = cms.RevocationInfoChoices([other])

        datas = cms.ContentInfo(
            {
                "content_type": cms.ContentType("signed_data"),
                "content": cms.SignedData(config),
            }
        )
        if self.attrs is False:
            tosign = self.datau
        else:
            tosign = datas["content"]["signer_infos"][0]["signed_attrs"].dump()
            tosign = b"\x31" + tosign[1:]

        signed_value_signature = self.sign(tosign)
        # signed_value_signature = core.OctetString(signed_value_signature)
        datas["content"]["signer_infos"][0]["signature"] = signed_value_signature

        tspresponse = self.get_tsp_response(signed_value_signature)
        if tspresponse is not None:
            datas["content"]["signer_infos"][0]["unsigned_attrs"] = tspresponse

        # open('signed-content-info', 'wb').write(datas.dump())
        return datas.dump()


class Signer1(Signer):  # noqa: E302
    def __init__(self, datau, key, cert, othercerts, hashalgo, attrs, signed_value, hsm,
        pss, timestampurl, timestampcredentials, timestamp_req_options, ocspurl, ocspissuer,
    ):
        if hsm is not None:
            keyid, cert = hsm.certificate()
            cert = cert2asn(cert, False)
            self.key = keyid
        else:
            cert = cert2asn(cert)
            self.key = key
        self.hsm = hsm
        self.timestampurl = timestampurl
        self.timestampcredentials = timestampcredentials
        self.timestamp_req_options = timestamp_req_options
        self.ocspurl = ocspurl
        self.ocspissuer = ocspissuer
        super().__init__(datau, cert, othercerts, hashalgo, attrs, signed_value, pss)

    def get_pss_salt_length(self) -> int:
        md = getattr(hashes, self.hashalgo.upper())
        if isinstance(self.key, keys.PrivateKeyInfo):
            salt_length = self.key.byte_size - md.digest_size - 2
            salt_length = md.digest_size
        else:
            if self.key is None:
                salt_length = md.digest_size
            else:
                salt_length = padding.calculate_max_pss_salt_length(self.key, md)
        return salt_length

    def get_ocsp_response(self, cert):
        if self.ocspissuer and self.ocspurl:
            response = fetch_ocsp_response(cert, self.ocspissuer, self.ocspurl)
            if response:
                return ocsp.OCSPResponse.load(response)
        return None

    def get_tsp_response(self, signed_value_signature):
        if self.timestampurl:
            return timestamp(
                signed_value_signature,
                self.hashalgo,
                self.timestampurl,
                self.timestampcredentials,
                self.timestamp_req_options,
            )
        return None

    def sign(self, tosign):
        if self.hsm is not None:
            signed_value_signature = self.hsm.sign(self.key, tosign, self.hashalgo)
        elif self.pss:
            md = getattr(hashes, self.hashalgo.upper())
            hasher = hashes.Hash(md(), backend=backends.default_backend())
            hasher.update(tosign)
            digest = hasher.finalize()
            signed_value_signature = self.key.sign(
                digest,
                padding.PSS(mgf=padding.MGF1(md()), salt_length=self.salt_length),
                utils.Prehashed(md()),
            )
        elif isinstance(self.key, ec.EllipticCurvePrivateKey):
            signed_value_signature = self.key.sign(
                tosign, ec.ECDSA(getattr(hashes, self.hashalgo.upper())())
            )
        else:
            signed_value_signature = self.key.sign(
                tosign, padding.PKCS1v15(), getattr(hashes, self.hashalgo.upper())()
            )
        return signed_value_signature

def sign(
    datau,
    key,
    cert,
    othercerts,
    hashalgo,
    attrs=True,
    signed_value=None,
    hsm=None,
    pss=False,
    timestampurl=None,
    timestampcredentials=None,
    timestamp_req_options=None,
    ocspurl=None,
    ocspissuer=None,
):
    cls = Signer1(datau, key, cert, othercerts, hashalgo, attrs, signed_value,
        hsm, pss, timestampurl, timestampcredentials, timestamp_req_options,
        ocspurl, ocspissuer
    )
    return cls.build()
