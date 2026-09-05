# endesive

[![PyPI version](https://img.shields.io/pypi/v/endesive.svg)](https://pypi.org/project/endesive/)
[![Python versions](https://img.shields.io/pypi/pyversions/endesive)](https://pypi.org/project/endesive/)

endesive is a Python library for creating and verifying digital signatures in:

- PDF documents (CMS/CAdES detached signatures, Adobe-compatible)
- S/MIME messages (sign, verify, encrypt, decrypt)
- Plain data streams (CMS detached signatures)
- XML documents (XAdES BES/T, enveloped and enveloping)

The project also provides PKCS#11/HSM integration and a large set of runnable examples.

## Features

- PDF signing and verification with optional TSA timestamping and OCSP data
- S/MIME signing/verification and envelope encryption/decryption
- CMS detached signatures for arbitrary binary/text payloads
- XAdES BES/T generation for XML workflows
- Hardware-backed signing through PKCS#11 (PyKCS11) and SSH agent support (paramiko)
- Verification result model exposing signature, hash, certificate, OCSP and TSP statuses

## Installation

Python requirement: **3.11+**

```bash
pip install endesive
```

From source:

```bash
pip install -e .
```

Development extras:

```bash
pip install -e ".[dev,docs]"
```

## Package Overview

- `endesive.pdf`
  - `endesive.pdf.cms.sign(...)`
  - `endesive.pdf.verify(...)`
  - `endesive.pdf.PDFVerifier`
- `endesive.email`
  - `endesive.email.sign(...)`
  - `endesive.email.verify(...)`
  - `endesive.email.encrypt(...)`
  - `endesive.email.decrypt(...)`
- `endesive.plain`
  - `endesive.plain.sign(...)`
  - `endesive.plain.verify(...)`
- `endesive.xades`
  - `endesive.xades.BES`
- `endesive.hsm`
  - `endesive.hsm.HSM`

## Quick Start

### 1) Sign a PDF

```python
import datetime
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12
from endesive.pdf import cms

with open("cert.p12", "rb") as fp:
    key, cert, cert_chain = pkcs12.load_key_and_certificates(
        fp.read(), b"password", backends.default_backend()
    )

with open("input.pdf", "rb") as fp:
    pdf_data = fp.read()

signing_date = datetime.datetime.now(datetime.UTC).strftime("D:%Y%m%d%H%M%S+00'00'")

pdf_signature_meta = {
    "sigpage": 0,
    "reason": "Approval",
    "location": "HQ",
    "contact": "security@example.com",
    "signingdate": signing_date,
}

signature_block = cms.sign(
    pdf_data,
    pdf_signature_meta,
    key,
    cert,
    cert_chain or [],
    "sha256",
)

with open("output-signed.pdf", "wb") as fp:
    fp.write(pdf_data)
    fp.write(signature_block)
```

### 2) Verify a PDF signature

```python
from endesive import pdf

trusted_certs = [open("ca-root.pem", "rb").read()]
signed_pdf = open("output-signed.pdf", "rb").read()

result, unsigned_tail = pdf.verify(signed_pdf, trusted_certs)

print("signature ok:", result.signatureok)
print("hash ok:", result.hashok)
print("certificate ok:", result.certok)
print("ocsp ok:", result.ocspok)
print("tsp ok:", result.tspok)
print("remaining unsigned data:", unsigned_tail is not None)
```

### 3) Sign/verify plain data (CMS detached)

```python
from endesive import plain

# detached_sig = plain.sign(data_bytes, private_key, certificate, cert_chain)
# verify_result = plain.verify(detached_sig, data_bytes, trusted_certs)
```

### 4) S/MIME operations

```python
from endesive import email

# signed_message = email.sign(data_bytes, private_key, certificate, cert_chain)
# verify_result = email.verify(signed_message_str, trusted_certs)
# encrypted_message = email.encrypt(data_bytes, recipient_certs, "aes256_cbc")
# decrypted_bytes = email.decrypt(encrypted_message_str, private_key)
```

### 5) XAdES

```python
from endesive.xades import BES

# bes = BES()
# xml_tree = bes.enveloped(data, cert, cert_bytes, signproc, tsp_url, tsp_credentials)
# xml_tree = bes.enveloping(...)
```

For complete XML flows, use the executable examples listed below.

## Examples

The [examples](examples) directory contains end-to-end scripts for certificate creation, data generation, signing, verification, HSM usage, timestamps, and advanced PDF signature appearance customization.

Useful starting points:

- Setup and test fixtures:
  - `examples/make-cert-ca.py`
  - `examples/make-cert-hsm.py`
  - `examples/make-pdf.py`
  - `examples/make-plain.py`
  - `examples/make-smime.py`
  - `examples/make-xml.py`
- PDF:
  - `examples/pdf-sign-cms.py`
  - `examples/pdf-verify.py`
  - `examples/pdf-timestamp-cms.py`
- Plain/CMS:
  - `examples/plain-sign-attr.py`
  - `examples/plain-sign-noattr.py`
  - `examples/plain-verify.py`
- S/MIME:
  - `examples/smime-sign-attr.py`
  - `examples/smime-encrypt.py`
  - `examples/smime-decrypt.py`
  - `examples/smime-verify.py`
- XAdES:
  - `examples/xml-hsm-certum-enveloped.py`
  - `examples/xml-hsm-certum-enveloping.py`

Recommended execution order:

1. Generate certificates.
2. Generate input documents/messages.
3. Run signing scripts.
4. Run corresponding verification scripts.

## Validation Tools

PDF validators:

- https://www.pdf-online.com/osa/validate.aspx
- https://demo.verapdf.org/
- https://pdfbox.apache.org/

Signature validation services:

- https://ec.europa.eu/cefdigital/DSS/webapp-demo/validation
- https://pkitools.net/pages/validator/pdf.html

## Development

Run tests:

```bash
make test
```

Run type checks:

```bash
make mypy
```

Build docs stubs:

```bash
make docs
```

## Dependencies

Runtime dependencies (from `pyproject.toml`):

- `cryptography`
- `asn1crypto`
- `certvalidator`
- `lxml`
- `pykcs11`
- `Pillow`
- `requests`
- `paramiko`
- `pypdf`
- `attrs`

## License

MIT, with additional license files for bundled components:

- `LICENSE`
- `LICENSE.pdf-annotate`
- `LICENSE.pyfpdf`
