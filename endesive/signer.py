# *-* coding: utf-8 *-*
from __future__ import unicode_literals

import sys
import types
import hashlib
import time
import requests
from base64 import b64encode
from datetime import datetime
from asn1crypto import cms, algos, core, keys, pem, tsp, x509, ocsp, util
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils, ec
from cryptography.hazmat import backends
from cryptography import x509 as cryptography_x509
from cryptography.x509 import ocsp as cryptography_ocsp


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
    """Extract OCSP URL from certificate's Authority Information Access extension"""
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
        )
        if response.status_code != 200:
            return None
        return response.content
    except requests.exceptions.ConnectionError:
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
            #'req_policy', ObjectIdentifier, {'optional': True}),
            "nonce": int(time.time() * 1000),
            "cert_req": True,
            #'extensions': tsp.Extensions()
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

    tspresp = requests.post(url, data=tspreq, headers=tspheaders, **req_options)
    if tspresp.headers.get("Content-Type", None) == "application/timestamp-reply":
        tspresp = tsp.TimeStampResp.load(tspresp.content)

        if tspresp["status"]["status"].native == "granted":
            attrs = [
                cms.CMSAttribute(
                    {
                        "type": cms.CMSAttributeType("signature_time_stamp_token"),
                        "values": cms.SetOfContentInfo(
                            [
                                cms.ContentInfo(
                                    {
                                        "content_type": cms.ContentType("signed_data"),
                                        "content": tspresp["time_stamp_token"][
                                            "content"
                                        ],
                                    }
                                )
                            ]
                        ),
                    }
                )
            ]
            return attrs
        else:
            raise ValueError("TimeStampResponse status is not granted")
    else:
        raise ValueError("TimeStampResponse has invalid content type")


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
    if signed_value is None:
        signed_value = getattr(hashlib, hashalgo)(datau).digest()
    signed_time = datetime.now(tz=util.timezone.utc)

    if hsm is not None:
        keyid, cert = hsm.certificate()
        cert = cert2asn(cert, False)
    else:
        cert = cert2asn(cert)

    certissuer = None
    certificates = []
    certificates.append(cert)
    for i in range(len(othercerts)):
        certo = cert2asn(othercerts[i])
        if certo.subject == cert.issuer:
            certissuer = certo
        certificates.append(certo)

    hashalgo = unicode(hashalgo) if sys.version[0] < "3" else hashalgo

    signer = {
        "version": "v1",
        "sid": cms.SignerIdentifier(
            {
                "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                    {
                        "issuer": cert.issuer,
                        "serial_number": cert.serial_number,
                    }
                ),
            }
        ),
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": hashalgo}),
        "signature": signed_value,
    }
    if not pss:
        signer["signature_algorithm"] = algos.SignedDigestAlgorithm(
            {"algorithm": "rsassa_pkcs1v15"}
        )
    else:
        md = getattr(hashes, hashalgo.upper())
        if isinstance(key, keys.PrivateKeyInfo):
            salt_length = key.byte_size - md.digest_size - 2
            salt_length = md.digest_size
        else:
            if key is None:
                salt_length = md.digest_size
            else:
                salt_length = padding.calculate_max_pss_salt_length(key, md)
        signer["signature_algorithm"] = algos.SignedDigestAlgorithm(
            {
                "algorithm": "rsassa_pss",
                "parameters": algos.RSASSAPSSParams(
                    {
                        "hash_algorithm": algos.DigestAlgorithm(
                            {"algorithm": hashalgo.lower()}
                        ),
                        "mask_gen_algorithm": algos.MaskGenAlgorithm(
                            {
                                "algorithm": algos.MaskGenAlgorithmId("mgf1"),
                                "parameters": {
                                    "algorithm": algos.DigestAlgorithmId(hashalgo.lower()),
                                },
                            }
                        ),
                        "salt_length": algos.Integer(salt_length),
                        "trailer_field": algos.TrailerField(1),
                    }
                ),
            }
        )

    if attrs:
        if attrs is True:
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
                                                cert.dump()
                                            ).digest(),
                                            "issuer_serial": tsp.IssuerSerial(
                                                {
                                                    "issuer": (
                                                        x509.GeneralName(
                                                            {
                                                                "directory_name": cert.issuer,
                                                            }
                                                        ),
                                                    ),
                                                    "serial_number": cert.serial_number,
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
                                                cert.dump()
                                            ).digest(),
                                            "issuer_serial": tsp.IssuerSerial(
                                                {
                                                    "issuer": (
                                                        x509.GeneralName(
                                                            {
                                                                "directory_name": cert.issuer,
                                                            }
                                                        ),
                                                    ),
                                                    "serial_number": cert.serial_number,
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
                        "values": (signed_value,),
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
        else:
            if isinstance(attrs, types.FunctionType):
                attrs = attrs(signed_value)
            signer["signed_attrs"] = attrs

    config = {
        "version": "v1",
        "digest_algorithms": cms.DigestAlgorithms(
            (algos.DigestAlgorithm({"algorithm": hashalgo}),)
        ),
        "encap_content_info": {
            "content_type": "data",
        },
        "certificates": certificates,
        "signer_infos": [
            signer,
        ],
    }
    if ocspurl and ocspissuer:
        ocsp_response = fetch_ocsp_response(cert, ocspissuer, ocspurl)
        if ocsp_response:
            ocsp_response = ocsp.OCSPResponse.load(ocsp_response)
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
    if attrs:
        tosign = datas["content"]["signer_infos"][0]["signed_attrs"].dump()
        tosign = b"\x31" + tosign[1:]
    else:
        tosign = datau
    if hsm is not None:
        signed_value_signature = hsm.sign(keyid, tosign, hashalgo)
    else:
        if pss:
            md = getattr(hashes, hashalgo.upper())
            hasher = hashes.Hash(md(), backend=backends.default_backend())
            hasher.update(tosign)
            digest = hasher.finalize()
            signed_value_signature = key.sign(
                digest,
                padding.PSS(mgf=padding.MGF1(md()), salt_length=salt_length),
                utils.Prehashed(md()),
            )
        else:
            if isinstance(key, ec.EllipticCurvePrivateKey):
                signed_value_signature = key.sign(
                    tosign, ec.ECDSA(getattr(hashes, hashalgo.upper())())
                )
            else:
                signed_value_signature = key.sign(
                    tosign, padding.PKCS1v15(), getattr(hashes, hashalgo.upper())()
                )

    if timestampurl is not None:
        datas["content"]["signer_infos"][0]["unsigned_attrs"] = timestamp(
            signed_value_signature,
            hashalgo,
            timestampurl,
            timestampcredentials,
            timestamp_req_options,
        )

    # signed_value_signature = core.OctetString(signed_value_signature)
    datas["content"]["signer_infos"][0]["signature"] = signed_value_signature

    # open('signed-content-info', 'wb').write(datas.dump())
    return datas.dump()
