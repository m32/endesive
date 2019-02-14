# -*- coding: utf-8 -*-
import base64
import datetime
import hashlib
import io
import uuid

from lxml import etree, builder

DS = builder.ElementMaker(
    namespace="http://www.w3.org/2000/09/xmldsig#",
    nsmap={
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    },
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


def ensure_str(x, encoding="utf-8", none_ok=False):
    if none_ok is True and x is None:
        return x
    if not isinstance(x, str):
        x = x.decode(encoding)
    return x


class BES:
    def __init__(self):
        self.guid = str(uuid.uuid1())
        self.time = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def sha256(self, data):
        h = hashlib.sha256(data).digest()
        return ensure_str(base64.b64encode(h))

    def _c14n(self, nodes, algorithm, inclusive_ns_prefixes=None):
        exclusive, with_comments = False, False

        if algorithm.startswith("http://www.w3.org/2001/10/xml-exc-c14n#"):
            exclusive = True
        if algorithm.endswith("#WithComments"):
            with_comments = True

        if not isinstance(nodes, list):
            nodes = [nodes]

        c14n = b""
        for node in nodes:
            c14n += etree.tostring(node, method="c14n", exclusive=exclusive, with_comments=with_comments,
                                   inclusive_ns_prefixes=inclusive_ns_prefixes)  # TODO: optimize if needed
        if exclusive is False:
            # TODO: there must be a nicer way to do this. See also:
            # http://www.w3.org/TR/xml-c14n, "namespace axis"
            # http://www.w3.org/TR/xml-c14n2/#sec-Namespace-Processing
            c14n = c14n.replace(b' xmlns=""', b'')
        return c14n

    def build(self, fname, data, smime, cert, certcontent, signproc, base64encode=True, withcomments=False):
        swithcomments = ""
        if withcomments:
            swithcomments = "#WithComments"
        if base64encode:
            data = ensure_str(base64.b64encode(data))
            signedobj = Object(
                data,
                Encoding="http://www.w3.org/2000/09/xmldsig#base64",
                MimeType=smime,
                Id="Object1_" + self.guid,
            )
        elif 0:
            signedobj = Object(
                data,
                MimeType='text/xml',
                Id="Object1_" + self.guid,
            )
        else:
            signedobj = Object(
                MimeType='text/xml',
                Id="Object1_" + self.guid,
            )
            tree = etree.parse(io.BytesIO(data))
            signedobj.append(tree.getroot())

        certdigest = self.sha256(certcontent)
        b64 = b''.join(base64.encodebytes(certcontent).split())
        certcontent = []
        for i in range(0, len(b64), 64):
            certcontent.append(b64[i:i + 64])
        certcontent = b'\n'.join(certcontent)
        certserialnumber = '%d' % cert.serial_number
        certissuer = []
        for k, v in (
                ('CN', 'common_name'),
                ('O', 'organization_name'),
                ('C', 'country_name'),
                ('serialNumber', 'serial_number'),
        ):
            try:
                v = cert.issuer.native[v]
                certissuer.append('%s=%s' % (k, v))
            except:
                pass
        certissuer = ','.join(certissuer)

        signedprop = SignedProperties(
            SignedSignatureProperties(
                SigningTime(
                    self.time
                ),
                SigningCertificate(
                    Cert(
                        CertDigest(
                            DigestMethod(
                                Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
                            ),
                            DigestValue(
                                certdigest,
                            ),
                        ),
                        IssuerSerial(
                            X509IssuerName(
                                certissuer,
                            ),
                            X509SerialNumber(
                                certserialnumber,
                            ),
                        ),
                    ),
                ),
                Id="SignedSignatureProperties_" + self.guid + "_04",
            ),
            SignedDataObjectProperties(
                DataObjectFormat(
                    Description("""\
MIME-Version: 1.0
Content-Type: %s
Content-Transfer-Encoding: binary
Content-Disposition: filename="%s"\
""" % (smime, fname),
                                ),
                    ObjectIdentifier(
                        Identifier(
                            "http://www.certum.pl/OIDAsURI/signedFile/1.2.616.1.113527.3.1.1.3.1",
                            Qualifier="OIDAsURI",
                        ),
                        Description(
                            u"Opis formatu dokumentu oraz jego pełna nazwa",
                        ),
                        DocumentationReferences(
                            DocumentationReference(
                                "http://www.certum.pl/OIDAsURI/signedFile.pdf",
                            ),
                        ),
                    ),
                    MimeType(
                        smime,
                    ),
                    ObjectReference="#Reference1_" + self.guid + "_29",
                ),
                Id="SignedDataObjectProperties_" + self.guid + "_45",
            ),
            Id="SignedProperties_" + self.guid + "_40",
        )

        canonicalizedxml = self._c14n(signedobj, '')
        digestvalue1 = self.sha256(canonicalizedxml)
        canonicalizedxml = self._c14n(signedprop, '')
        digestvalue2 = self.sha256(canonicalizedxml)

        signedinfo = SignedInfo(
            CanonicalizationMethod(
                Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            ),
            SignatureMethod(
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            ),
            Reference(
                Transforms(
                    Transform(
                        Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" + swithcomments,
                    )
                ),
                DigestMethod(
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
                ),
                DigestValue(
                    digestvalue1,
                ),
                URI="#Object1_" + self.guid,
                Id="Reference1_" + self.guid + "_29",
            ),
            Reference(
                DigestMethod(
                    Algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
                ),
                DigestValue(
                    digestvalue2,
                ),
                Id="SignedProperties-Reference_" + self.guid + "_26",
                Type="http://uri.etsi.org/01903#SignedProperties",
                URI="#SignedProperties_" + self.guid + "_40",
            ),
            Id="SignedInfo_" + self.guid + "_4f",
        )
        canonicalizedxml = self._c14n(signedinfo, '')
        signature = signproc(canonicalizedxml, 'sha256')
        actualdigestencoded = ensure_str(base64.b64encode(signature))
        digestvalue3 = []
        for i in range(0, len(actualdigestencoded), 64):
            digestvalue3.append(actualdigestencoded[i:i + 64])
        digestvalue3 = '\n'.join(digestvalue3)

        DOC = Signature(
            signedinfo,
            SignatureValue(
                digestvalue3,
                Id="SignatureValue_" + self.guid + "_5c",
            ),
            KeyInfo(
                X509Data(
                    X509Certificate(
                        certcontent.decode()
                    ),
                ),
                Id="KeyInfo_" + self.guid + "_2a",
            ),
            Object(
                QualifyingProperties(
                    signedprop,
                    UnsignedProperties(
                        Id="UnsignedProperties_" + self.guid + "_5b",
                    ),
                    Id="QualifyingProperties_" + self.guid + "_4d",
                    Target="#Signature_" + self.guid + "_17",
                ),
            ),
            signedobj,
            Id="Signature_" + self.guid + "_17",
        )
        return DOC
