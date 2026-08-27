# https://dss.nowina.lu/validation
# https://signatures-conformance-checker.etsi.org/pub/index.php
#
from __future__ import annotations

import base64
import datetime
import hashlib
import io
import logging
import secrets
import uuid
from typing import Any

import requests
from asn1crypto import algos, tsp
from cryptography.x509.oid import NameOID
from lxml import builder, etree

logger = logging.getLogger(__name__)

DEFAULT_HTTP_TIMEOUT = 10

DS = builder.ElementMaker(
    namespace="http://www.w3.org/2000/09/xmldsig#",
    nsmap={"ds": "http://www.w3.org/2000/09/xmldsig#"},
)
CanonicalizationMethod = DS.CanonicalizationMethod
DigestMethod = DS.DigestMethod
DigestValue = DS.DigestValue
KeyInfo = DS.KeyInfo
Object = DS.Object
Reference = DS.Reference
Signature = DS.Signature
SignatureMethod = DS.SignatureMethod
SignatureValue = DS.SignatureValue
SignedInfo = DS.SignedInfo
Transform = DS.Transform
Transforms = DS.Transforms
X509Certificate = DS.X509Certificate
X509Data = DS.X509Data
X509IssuerName = DS.X509IssuerName
X509SerialNumber = DS.X509SerialNumber
XPath = DS.XPath

XADES = builder.ElementMaker(
    namespace="http://uri.etsi.org/01903/v1.3.2#",
    nsmap={
        "xades": "http://uri.etsi.org/01903/v1.3.2#",
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    },
)
Cert = XADES.Cert
CertDigest = XADES.CertDigest
DataObjectFormat = XADES.DataObjectFormat
Description = XADES.Description
DocumentationReference = XADES.DocumentationReference
DocumentationReferences = XADES.DocumentationReferences
Identifier = XADES.Identifier
IssuerSerial = XADES.IssuerSerial
MimeType = XADES.MimeType
ObjectIdentifier = XADES.ObjectIdentifier
QualifyingProperties = XADES.QualifyingProperties
SignedDataObjectProperties = XADES.SignedDataObjectProperties
SignedProperties = XADES.SignedProperties
SignedSignatureProperties = XADES.SignedSignatureProperties
SigningCertificate = XADES.SigningCertificate
SigningTime = XADES.SigningTime
UnsignedProperties = XADES.UnsignedProperties
UnsignedSignatureProperties = XADES.UnsignedSignatureProperties
SignatureTimeStamp = XADES.SignatureTimeStamp
EncapsulatedTimeStamp = XADES.EncapsulatedTimeStamp


OID_NAMES = {
    NameOID.COMMON_NAME: "CN",
    NameOID.COUNTRY_NAME: "C",
    NameOID.DOMAIN_COMPONENT: "DC",
    NameOID.EMAIL_ADDRESS: "E",
    NameOID.GIVEN_NAME: "G",
    NameOID.LOCALITY_NAME: "L",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.SURNAME: "SN",
}


class BES:
    """XAdES BES (Baseline Signature Electronically Supported) implementation."""

    def __init__(self) -> None:
        """Initialize BES signer."""
        self.guid: str = str(uuid.uuid4())
        self.time: str = datetime.datetime.now(datetime.UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    def _sha256(self, data: bytes) -> str:
        """Compute SHA256 hash and encode as base64.

        Args:
            data: Data to hash

        Returns:
            Base64 encoded SHA256 digest
        """
        h = hashlib.sha256(data).digest()
        return base64.b64encode(h).decode()

    def _base64(self, data: bytes) -> str:
        """Encode data as base64 with line breaks.

        Args:
            data: Data to encode

        Returns:
            Base64 encoded string with 64-char line wrapping
        """
        b64 = b"".join(base64.encodebytes(data).split())
        result = []
        for i in range(0, len(b64), 64):
            result.append(b64[i : i + 64])
        result = b"\n".join(result).decode()
        return result

    def _get_rdns_name(self, rdns: Any) -> str:
        """Get Distinguished Name from RDN sequence.

        Args:
            rdns: RDN (Relative Distinguished Name) sequence

        Returns:
            Distinguished Name string
        """
        name = ""
        for rdn in rdns:
            for attr in rdn._attributes:
                if len(name) > 0:
                    name = f"{name},"
                if attr.oid in OID_NAMES:
                    name = f"{name}{OID_NAMES[attr.oid]}"
                else:
                    name = f"{name}{attr.oid.dotted_string}"
                    s = "".join([f"{int(b):02x}" for b in attr.value.encode()])
                    s = f"#0C{len(attr.value):02X}{s}"
                    name = f"{name}={s}"
                    continue
                name = f"{name}={attr.value}"
        return name

    def _c14n(self, nodes, algorithm, inclusive_ns_prefixes=None):
        exclusive, with_comments = False, False

        if algorithm.startswith("http://www.w3.org/2001/10/xml-exc-c14n#"):
            exclusive = True
        if algorithm.endswith("#WithComments"):
            with_comments = True

        data = etree.tostring(
            nodes, encoding="UTF-8", xml_declaration=True, standalone=False
        )
        data = io.BytesIO(data)
        tree = etree.parse(data)
        data = io.BytesIO()
        tree.write_c14n(
            data,
            exclusive=exclusive,
            with_comments=with_comments,
            compression=0,
            inclusive_ns_prefixes=inclusive_ns_prefixes,
        )
        c14n = data.getvalue()

        return c14n

    def _unsignedproperties(self, signed_value, tspurl, tspcred, hashalgo="sha256"):
        if tspurl is None:
            unsignedproperties = UnsignedProperties(
                Id=f"UnsignedProperties_{self.guid}_02"
            )
        else:
            tspreq = tsp.TimeStampReq(
                {
                    "version": 1,
                    "message_imprint": tsp.MessageImprint(
                        {
                            "hash_algorithm": algos.DigestAlgorithm(
                                {"algorithm": hashalgo}
                            ),
                            "hashed_message": signed_value.encode(),
                        }
                    ),
                    #'req_policy', ObjectIdentifier, {'optional': True}),
                    "nonce": secrets.randbits(64),
                    "cert_req": True,
                    #'extensions': tsp.Extensions()
                }
            )
            tspreq = tspreq.dump()

            tspheaders = {"Content-Type": "application/timestamp-query"}
            if tspcred is not None:
                username = tspcred.get("username", None)
                password = tspcred.get("password", None)
                if username and password:
                    auth_header_value = base64.b64encode(
                        bytes(f"{username}:{password}", "utf-8")
                    ).decode("ascii")
                    tspheaders["Authorization"] = f"Basic {auth_header_value}"
            tspresp = requests.post(
                tspurl,
                data=tspreq,
                headers=tspheaders,
                timeout=DEFAULT_HTTP_TIMEOUT,
            )
            if (
                tspresp.headers.get("Content-Type", None)
                == "application/timestamp-reply"
            ):
                tspresp = tsp.TimeStampResp.load(tspresp.content)

                if tspresp["status"]["status"].native == "granted":
                    attr = self._base64(tspresp["time_stamp_token"].dump())
                else:
                    raise ValueError("TimeStampResponse status is not granted")
            else:
                raise ValueError("TimeStampResponse has invalid content type")

            unsignedproperties = UnsignedProperties(
                UnsignedSignatureProperties(
                    SignatureTimeStamp(
                        CanonicalizationMethod(
                            Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        ),
                        EncapsulatedTimeStamp(
                            attr, Encoding="http://uri.etsi.org/01903/v1.2.2#DER"
                        ),
                        Id=f"SignatureTimeStamp_{self.guid}",
                    )
                ),
                Id=f"UnsignedProperties_{self.guid}_02",
            )
        return unsignedproperties

    def enveloped(
        self, data, cert, certcontent, signproc, tspurl, tspcred, signaturemethod=None
    ):
        tree = etree.parse(io.BytesIO(data))
        signedobj = tree.getroot()
        canonicalizedxml = self._c14n(signedobj, "")
        digestvalue1 = self._sha256(canonicalizedxml)

        nsmap = signedobj.nsmap.copy()
        nsmap.update(
            {
                "xades": "http://uri.etsi.org/01903/v1.3.2#",
                "ds": "http://www.w3.org/2000/09/xmldsig#",
            }
        )
        siXADES = builder.ElementMaker(
            namespace="http://uri.etsi.org/01903/v1.3.2#", nsmap=nsmap
        )
        SignedProperties = siXADES.SignedProperties

        nsmap = signedobj.nsmap.copy()
        nsmap.update({"ds": "http://www.w3.org/2000/09/xmldsig#"})
        siDS = builder.ElementMaker(
            namespace="http://www.w3.org/2000/09/xmldsig#", nsmap=nsmap
        )
        SignedInfo = siDS.SignedInfo

        certdigest = self._sha256(certcontent)
        certcontent = self._base64(certcontent)
        certserialnumber = f"{cert.serial_number:d}"
        certissuer = self._get_rdns_name(cert.issuer.rdns)

        signedproperties = SignedProperties(
            SignedSignatureProperties(
                SigningTime(self.time),
                SigningCertificate(
                    Cert(
                        CertDigest(
                            DigestMethod(
                                Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
                            ),
                            DigestValue(certdigest),
                        ),
                        IssuerSerial(
                            X509IssuerName(certissuer),
                            X509SerialNumber(certserialnumber),
                        ),
                    )
                ),
                Id=f"SignedSignatureProperties_{self.guid}_5d",
            ),
            SignedDataObjectProperties(
                DataObjectFormat(
                    Description(
                        """\
MIME-Version: 1.0
Content-Type: text/xml
Content-Transfer-Encoding: binary
Content-Disposition: filename="document.xml"\
"""
                    ),
                    ObjectIdentifier(
                        Identifier(
                            "http://www.certum.pl/OIDAsURI/signedFile/1.2.616.1.113527.3.1.1.3.1",
                            Qualifier="OIDAsURI",
                        ),
                        Description("Opis formatu dokumentu oraz jego pełna nazwa"),
                        DocumentationReferences(
                            DocumentationReference(
                                "http://www.certum.pl/OIDAsURI/signedFile.pdf"
                            )
                        ),
                    ),
                    MimeType("text/xml"),
                    ObjectReference=f"#Reference1_{self.guid}_70",
                ),
                Id=f"SignedDataObjectProperties_{self.guid}_1c",
            ),
            Id=f"SignedProperties_{self.guid}_19",
        )

        canonicalizedxml = self._c14n(signedproperties, "")
        digestvalue2 = self._sha256(canonicalizedxml)
        logger.debug("canonicalizedxml: %s", canonicalizedxml)
        logger.debug("digestvalue2: %s", digestvalue2)

        unsignedproperties = self._unsignedproperties(
            digestvalue2, tspurl, tspcred, "sha256"
        )

        if signaturemethod is None:
            signaturemethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        signedinfo = SignedInfo(
            CanonicalizationMethod(
                Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            ),
            SignatureMethod(Algorithm=signaturemethod),
            Reference(
                Transforms(
                    Transform(
                        XPath("not(ancestor-or-self::ds:Signature)"),
                        Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116",
                    )
                ),
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue1),
                Id=f"Reference1_{self.guid}_70",
                URI="",
            ),
            Reference(
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue2),
                Id=f"SignedProperties-Reference_{self.guid}_7f",
                Type="http://uri.etsi.org/01903#SignedProperties",
                URI=f"#SignedProperties_{self.guid}_19",
            ),
            Id=f"SignedInfo_{self.guid}_16",
        )

        canonicalizedxml = self._c14n(signedinfo, "")
        logger.debug("canonicalizedxml: %s", canonicalizedxml)

        signature = signproc(canonicalizedxml, "sha256")
        actualdigestencoded = base64.b64encode(signature).decode()
        digestvalue3 = []
        for i in range(0, len(actualdigestencoded), 64):
            digestvalue3.append(actualdigestencoded[i : i + 64])
        digestvalue3 = "\n".join(digestvalue3)

        DOC = Signature(
            signedinfo,
            SignatureValue(digestvalue3, Id=f"SignatureValue_{self.guid}_05"),
            KeyInfo(
                X509Data(X509Certificate(certcontent)),
                Id=f"KeyInfo_{self.guid}_73",
            ),
            Object(
                QualifyingProperties(
                    signedproperties,
                    unsignedproperties,
                    Id=f"QualifyingProperties_{self.guid}_14",
                    Target=f"#Signature_{self.guid}_4e",
                )
            ),
            Id=f"Signature_{self.guid}_4e",
        )

        signedobj.append(DOC)
        return tree

    def enveloping(
        self,
        fname,
        data,
        smime,
        cert,
        certcontent,
        signproc,
        base64encode=True,
        withcomments=False,
        detached=False,
        tspurl=None,
        tspcred=None,
        signaturemethod=None,
    ):
        swithcomments = ""
        if withcomments:
            swithcomments = "#WithComments"
        if detached:
            tree = etree.parse(io.BytesIO(data))
            signedobj = tree.getroot()
            canonicalizedxml = self._c14n(signedobj, "")
            digestvalue1 = self._sha256(canonicalizedxml)
            URI = fname
            signedobj = None
        else:
            if base64encode:
                data = base64.b64encode(data).decode()
                signedobj = Object(
                    data,
                    Encoding="http://www.w3.org/2000/09/xmldsig#base64",
                    MimeType=smime,
                    Id="Object1_" + self.guid,
                )
                URI = "#Object1_" + self.guid
            elif 0:
                signedobj = Object(data, MimeType="text/xml", Id="Object1_" + self.guid)
                URI = "#Object1_" + self.guid
            else:
                signedobj = Object(MimeType="text/xml", Id="Object1_" + self.guid)
                tree = etree.parse(io.BytesIO(data))
                signedobj.append(tree.getroot())
                URI = "#Object1_" + self.guid
            canonicalizedxml = self._c14n(signedobj, "")
            digestvalue1 = self._sha256(canonicalizedxml)

        certdigest = self._sha256(certcontent)
        certcontent = self._base64(certcontent)
        certserialnumber = f"{cert.serial_number:d}"
        certissuer = self._get_rdns_name(cert.issuer.rdns)

        signedprop = SignedProperties(
            SignedSignatureProperties(
                SigningTime(self.time),
                SigningCertificate(
                    Cert(
                        CertDigest(
                            DigestMethod(
                                Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"
                            ),
                            DigestValue(certdigest),
                        ),
                        IssuerSerial(
                            X509IssuerName(certissuer),
                            X509SerialNumber(certserialnumber),
                        ),
                    )
                ),
                Id=f"SignedSignatureProperties_{self.guid}_5d",
            ),
            SignedDataObjectProperties(
                DataObjectFormat(
                    Description(
                        f"""\
MIME-Version: 1.0
Content-Type: {smime}
Content-Transfer-Encoding: binary
Content-Disposition: filename="{fname}"\
"""
                    ),
                    ObjectIdentifier(
                        Identifier(
                            "http://www.certum.pl/OIDAsURI/signedFile/1.2.616.1.113527.3.1.1.3.1",
                            Qualifier="OIDAsURI",
                        ),
                        Description("Opis formatu dokumentu oraz jego pełna nazwa"),
                        DocumentationReferences(
                            DocumentationReference(
                                "http://www.certum.pl/OIDAsURI/signedFile.pdf"
                            )
                        ),
                    ),
                    MimeType(smime),
                    ObjectReference=f"#Reference1_{self.guid}_70",
                ),
                Id=f"SignedDataObjectProperties_{self.guid}_1c",
            ),
            Id=f"SignedProperties_{self.guid}_19",
        )

        canonicalizedxml = self._c14n(signedprop, "")
        digestvalue2 = self._sha256(canonicalizedxml)
        logger.debug("canonicalizedxml: %s", canonicalizedxml)
        logger.debug("digestvalue2: %s", digestvalue2)

        if signaturemethod is None:
            signaturemethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        signedinfo = SignedInfo(
            CanonicalizationMethod(
                Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            ),
            SignatureMethod(Algorithm=signaturemethod),
            Reference(
                Transforms(
                    Transform(
                        Algorithm=f"http://www.w3.org/TR/2001/REC-xml-c14n-20010315{swithcomments}"
                    )
                ),
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue1),
                URI=URI,
                Id=f"Reference1_{self.guid}_70",
            ),
            Reference(
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue2),
                Id=f"SignedProperties-Reference_{self.guid}_7f",
                Type="http://uri.etsi.org/01903#SignedProperties",
                URI=f"#SignedProperties_{self.guid}_19",
            ),
            Id=f"SignedInfo_{self.guid}_16",
        )

        canonicalizedxml = self._c14n(signedinfo, "")
        logger.debug("canonicalizedxml: %s", canonicalizedxml)

        signature = signproc(canonicalizedxml, "sha256")
        actualdigestencoded = base64.b64encode(signature).decode()
        digestvalue3 = []
        for i in range(0, len(actualdigestencoded), 64):
            digestvalue3.append(actualdigestencoded[i : i + 64])
        digestvalue3 = "\n".join(digestvalue3)

        unsignedproperties = self._unsignedproperties(
            digestvalue2, tspurl, tspcred, "sha256"
        )

        DOC = Signature(
            signedinfo,
            SignatureValue(digestvalue3, Id=f"SignatureValue_{self.guid}_05"),
            KeyInfo(
                X509Data(X509Certificate(certcontent)),
                Id=f"KeyInfo_{self.guid}_73",
            ),
            Object(
                QualifyingProperties(
                    signedprop,
                    unsignedproperties,
                    Id=f"QualifyingProperties_{self.guid}_14",
                    Target=f"#Signature_{self.guid}_4e",
                )
            ),
            Id=f"Signature_{self.guid}_4e",
        )
        if signedobj is not None:
            DOC.append(signedobj)
        return DOC
