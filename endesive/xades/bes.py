# -*- coding: utf-8 -*-
# https://dss.nowina.lu/validation
# https://signatures-conformance-checker.etsi.org/pub/index.php
#
import base64
from endesive import xades
import time
import datetime
import hashlib
import io
import uuid

from cryptography.x509.oid import NameOID
from lxml import etree, builder
import requests
from asn1crypto import cms, algos, core, keys, pem, tsp, x509, util

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
    debug = False

    def __init__(self):
        self.guid = str(uuid.uuid1())
        self.time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def sha256(self, data):
        h = hashlib.sha256(data).digest()
        return base64.b64encode(h).decode()

    def base64(self, data):
        b64 = b"".join(base64.encodebytes(data).split())
        data = []
        for i in range(0, len(b64), 64):
            data.append(b64[i : i + 64])
        data = b"\n".join(data).decode()
        return data

    def get_rdns_name(self, rdns):
        name = ""
        for rdn in rdns:
            for attr in rdn._attributes:
                if len(name) > 0:
                    name = name + ","
                if attr.oid in OID_NAMES:
                    name = name + OID_NAMES[attr.oid]
                else:
                    name = name + attr.oid.dotted_string
                    s = "".join(["%02x" % int(b) for b in attr.value.encode()])
                    s = "#0C%02X%s" % (len(attr.value), s)
                    name = name + "=" + s
                    continue
                name = name + "=" + attr.value
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

    def unsignedpropertied(self, signed_value, tspurl, tspcred, hashalgo="sha256"):
        if tspurl is None:
            unsignedproperties = UnsignedProperties(
                Id="UnsignedProperties_" + self.guid + self.mapa["_5d"]
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
                    "nonce": int(time.time() * 1000),
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
                        bytes(username + ":" + password, "utf-8")
                    ).decode("ascii")
                    tspheaders["Authorization"] = f"Basic {auth_header_value}"
            tspresp = requests.post(tspurl, data=tspreq, headers=tspheaders)
            if (
                tspresp.headers.get("Content-Type", None)
                == "application/timestamp-reply"
            ):
                tspresp = tsp.TimeStampResp.load(tspresp.content)

                if tspresp["status"]["status"].native == "granted":
                    attr = self.base64(tspresp["time_stamp_token"].dump())
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
                        Id="SignatureTimeStamp_" + self.guid,
                    )
                ),
                Id="UnsignedProperties_" + self.guid + self.mapa["_5d"],
            )
        return unsignedproperties

    mapa = {
        "_02": "_5d",
        "_2f": "_70",
        "_43": "_1c",
        "_20": "_7f",
        "_46": "_19",
        "_49": "_16",
        "_5a": "_05",
        "_2c": "_73",
        "_4b": "_14",
        "_11": "_4e",
        "_5d": "_02",
    }

    def enveloped(self, data, cert, certcontent, signproc, tspurl, tspcred):
        tree = etree.parse(io.BytesIO(data))
        signedobj = tree.getroot()
        canonicalizedxml = self._c14n(signedobj, "")
        digestvalue1 = self.sha256(canonicalizedxml)

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

        certdigest = self.sha256(certcontent)
        certcontent = self.base64(certcontent)
        certserialnumber = "%d" % cert.serial_number
        certissuer = self.get_rdns_name(cert.issuer.rdns)
        if self.debug:
            self.guid = "279d6285-779c-4449-9c92-6bf3f7edacc2"
            self.time = "2020-11-24T00:32:43Z"
            certissuer = "2.5.4.97=#0C10564154504C2D35313730333539343538,CN=Certum QCA 2017,O=Asseco Data Systems S.A.,C=PL"

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
                Id="SignedSignatureProperties_" + self.guid + self.mapa["_02"],
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
                    ObjectReference="#Reference1_" + self.guid + self.mapa["_2f"],
                ),
                Id="SignedDataObjectProperties_" + self.guid + self.mapa["_43"],
            ),
            Id="SignedProperties_" + self.guid + self.mapa["_46"],
        )

        canonicalizedxml = self._c14n(signedproperties, "")
        digestvalue2 = self.sha256(canonicalizedxml)
        if self.debug:
            print("*" * 20, "enveloped signedproperties")
            print(canonicalizedxml)
            print("digest:", digestvalue2)

        unsignedproperties = self.unsignedpropertied(
            digestvalue2, tspurl, tspcred, "sha256"
        )

        signedinfo = SignedInfo(
            CanonicalizationMethod(
                Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            ),
            SignatureMethod(
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            ),
            Reference(
                Transforms(
                    Transform(
                        XPath("not(ancestor-or-self::ds:Signature)"),
                        Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116",
                    )
                ),
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue1),
                Id="Reference1_" + self.guid + self.mapa["_2f"],
                URI="",
            ),
            Reference(
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue2),
                Id="SignedProperties-Reference_" + self.guid + self.mapa["_20"],
                Type="http://uri.etsi.org/01903#SignedProperties",
                URI="#SignedProperties_" + self.guid + self.mapa["_46"],
            ),
            Id="SignedInfo_" + self.guid + self.mapa["_49"],
        )

        canonicalizedxml = self._c14n(signedinfo, "")
        if self.debug:
            print("*" * 20, "enveloped signedinfo")
            print(canonicalizedxml)
        signature = signproc(canonicalizedxml, "sha256")
        actualdigestencoded = base64.b64encode(signature).decode()
        digestvalue3 = []
        for i in range(0, len(actualdigestencoded), 64):
            digestvalue3.append(actualdigestencoded[i : i + 64])
        digestvalue3 = "\n".join(digestvalue3)

        DOC = Signature(
            signedinfo,
            SignatureValue(
                digestvalue3, Id="SignatureValue_" + self.guid + self.mapa["_5a"]
            ),
            KeyInfo(
                X509Data(X509Certificate(certcontent)),
                Id="KeyInfo_" + self.guid + self.mapa["_2c"],
            ),
            Object(
                QualifyingProperties(
                    signedproperties,
                    unsignedproperties,
                    Id="QualifyingProperties_" + self.guid + self.mapa["_4b"],
                    Target="#Signature_" + self.guid + self.mapa["_11"],
                )
            ),
            Id="Signature_" + self.guid + self.mapa["_11"],
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
    ):
        swithcomments = ""
        if withcomments:
            swithcomments = "#WithComments"
        if detached:
            tree = etree.parse(io.BytesIO(data))
            signedobj = tree.getroot()
            canonicalizedxml = self._c14n(signedobj, "")
            digestvalue1 = self.sha256(canonicalizedxml)
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
            digestvalue1 = self.sha256(canonicalizedxml)

        certdigest = self.sha256(certcontent)
        certcontent = self.base64(certcontent)
        certserialnumber = "%d" % cert.serial_number
        certissuer = self.get_rdns_name(cert.issuer.rdns)

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
                Id="SignedSignatureProperties_" + self.guid + self.mapa["_02"],
            ),
            SignedDataObjectProperties(
                DataObjectFormat(
                    Description(
                        """\
MIME-Version: 1.0
Content-Type: %s
Content-Transfer-Encoding: binary
Content-Disposition: filename="%s"\
"""
                        % (smime, fname)
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
                    ObjectReference="#Reference1_" + self.guid + self.mapa["_2f"],
                ),
                Id="SignedDataObjectProperties_" + self.guid + self.mapa["_43"],
            ),
            Id="SignedProperties_" + self.guid + self.mapa["_46"],
        )

        canonicalizedxml = self._c14n(signedprop, "")
        digestvalue2 = self.sha256(canonicalizedxml)
        if self.debug:
            print("*" * 20, "build signedprop")
            print(canonicalizedxml)
            print("digest:", digestvalue2)

        signedinfo = SignedInfo(
            CanonicalizationMethod(
                Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            ),
            SignatureMethod(
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
            ),
            Reference(
                Transforms(
                    Transform(
                        Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
                        + swithcomments
                    )
                ),
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue1),
                URI=URI,
                Id="Reference1_" + self.guid + self.mapa["_2f"],
            ),
            Reference(
                DigestMethod(Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DigestValue(digestvalue2),
                Id="SignedProperties-Reference_" + self.guid + self.mapa["_20"],
                Type="http://uri.etsi.org/01903#SignedProperties",
                URI="#SignedProperties_" + self.guid + self.mapa["_46"],
            ),
            Id="SignedInfo_" + self.guid + self.mapa["_49"],
        )

        canonicalizedxml = self._c14n(signedinfo, "")
        if self.debug:
            print("*" * 20, "build signedinfo")
            print(canonicalizedxml)
        signature = signproc(canonicalizedxml, "sha256")
        actualdigestencoded = base64.b64encode(signature).decode()
        digestvalue3 = []
        for i in range(0, len(actualdigestencoded), 64):
            digestvalue3.append(actualdigestencoded[i : i + 64])
        digestvalue3 = "\n".join(digestvalue3)

        unsignedproperties = self.unsignedpropertied(
            digestvalue2, tspurl, tspcred, "sha256"
        )

        DOC = Signature(
            signedinfo,
            SignatureValue(
                digestvalue3, Id="SignatureValue_" + self.guid + self.mapa["_5a"]
            ),
            KeyInfo(
                X509Data(X509Certificate(certcontent)),
                Id="KeyInfo_" + self.guid + self.mapa["_2c"],
            ),
            Object(
                QualifyingProperties(
                    signedprop,
                    unsignedproperties,
                    Id="QualifyingProperties_" + self.guid + self.mapa["_4b"],
                    Target="#Signature_" + self.guid + self.mapa["_11"],
                )
            ),
            Id="Signature_" + self.guid + self.mapa["_11"],
        )
        if signedobj is not None:
            DOC.append(signedobj)
        return DOC
