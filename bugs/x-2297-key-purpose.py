Certificado emitido por la Sub-CA real de demo del proyecto (`tests/fixtures/demo2_ca.sub.*`),
con el mismo perfil de extensiones que un certificado legítimo del proyecto, pero con
`KeyUsage` que excluye explícitamente firma:

```python
builder = builder.add_extension(
    cx509.KeyUsage(
        digital_signature=False,      # explícitamente NO permitido para firmar
        content_commitment=False,     # explícitamente NO permitido para no-repudio
        key_encipherment=True, data_encipherment=True,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    ),
    critical=True,
)
```

Firmado con este certificado y verificado:
```python
datas = pdf.cms.sign(datau, dct, restricted_key, restricted_cert, [sub_cert], 'sha256')
signed_pdf = datau + datas
print(pdf.verify(signed_pdf, trusted))
```

Salida real:
```
[(True, True, True)]
```

`certok=True` para una firma hecha con un certificado que declara, en su propia extensión
KeyUsage, que su clave no debe usarse ni para firmar ni para no-repudio.
