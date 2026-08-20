# Payload
Una CertificateList (CRL) real y bien formada, envuelta como
RevocationInfoChoice de tipo 'crl' (la otra alternativa válida del
mismo campo ASN.1, junto a 'other'/ocsp_response, según RFC 5652).

Invocación:
  PDFVerifier.verify_ocsp_data(cert, othercerts, crldata)
(ver script completo en Prueba de concepto)

# Response
Traceback (most recent call last):
  File "poc.py", line 38, in <module>
    ok, info = v.verify_ocsp_data(FakeCert(), [], crldata)
  File "endesive/pdf/verify.py", line 204, in verify_ocsp_data
    if crl1.native["other_rev_info_format"] != "ocsp_response":
KeyError: 'other_rev_info_format'
