```python
from cryptography.x509.verification import PolicyBuilder, ClientVerifier
print([m for m in dir(PolicyBuilder) if not m.startswith('_')])
print([m for m in dir(ClientVerifier) if not m.startswith('_')])
```

Salida real:
```
['build_client_verifier', 'build_server_verifier', 'extension_policies', 'max_chain_depth', 'store', 'time']
['policy', 'store', 'verify']
```

```
$ grep -n "^import\|^from" endesive/verifier.py
import os
import glob
import hashlib
import datetime
from asn1crypto import x509, core, pem, cms
import certifi
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.x509.verification import PolicyBuilder, Store
from cryptography import x509 as cx509
from cryptography.hazmat.backends import default_backend
```

Ni `requests` ni `urllib` aparecen — cero capacidad de red en este archivo.
