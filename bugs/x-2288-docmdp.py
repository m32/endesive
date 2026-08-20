```python
import test_cert
from endesive import pdf

p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
datau = open('fixtures/pdf.pdf', 'rb').read()

# Firma 1: CERTIFICACIÓN -- declara sigandcertify (DocMDP P=1, "no más cambios")
dct1 = {
    'sigflags': 3, 'contact': 'certifier@example.com', 'location': 'PoC',
    'signingdate': "20260722120000+00'00'",
    'reason': 'Certification signature - NO CHANGES ALLOWED AFTER THIS',
    'sigandcertify': True,
}
datas1 = pdf.cms.sign(datau, dct1, p12[0], p12[1], p12[2], 'sha256')
step1 = datau + datas1

with open(test_cert.ca_root_cert, 'rb') as fh:
    trusted = (fh.read(),)
print("verify() tras la certificación:", pdf.verify(step1, trusted))

# Firma 2: se añade OTRA firma sobre el documento YA CERTIFICADO como "sin cambios"
dct2 = {
    'sigflags': 3, 'contact': 'attacker@example.com', 'location': 'PoC',
    'signingdate': "20260722130000+00'00'",
    'reason': 'A second signature added AFTER certification said no changes allowed',
}
datas2 = pdf.cms.sign(step1, dct2, p12[0], p12[1], p12[2], 'sha256')
step2 = step1 + datas2
print("verify() tras la SEGUNDA firma (violando la certificación):", pdf.verify(step2, trusted))
```

Salida real:
```
verify() tras la certificación: [(True, True, True)]

verify() tras la SEGUNDA firma (violando la certificación): [(True, True, True), (True, True, True)]
```

Ambas firmas se reportan como completamente válidas — sin ninguna indicación de que la
segunda viola la política que la primera declaró explícitamente.
