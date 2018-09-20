# *-* coding: utf-8 *-*
import hashlib

from endesive import signer
from . import fpdf


class FPDF(fpdf.FPDF):
    signer = True

    def pkcs11_aligned(self, data):
        data = ''.join(['%02x' % i for i in data])
        nb = 0x4000 - len(data)
        data = data + '0' * (0x4000 - len(data))
        return data

    def pkcs11_setup(self, config, key, cert, othercerts, algomd):
        self.pkcs11config = config
        self.pkcs11zeros = self.pkcs11_aligned([0])
        self.pkcs11annot = 0
        self.pkcs11key = key
        self.pkcs11cert = cert
        self.pkcs11certs = othercerts
        self.pkcs11algomd = algomd

    def pkcs11_signature(self):
        self._newobj()
        self.pkcs11annot = self.n
        self._out('<</F 132/Type/Annot/Subtype/Widget/Rect[0 0 0 0]/FT/Sig/DR<<>>/T(signature%d)/V %d 0 R>>' % (
        self.pkcs11annot, self.pkcs11annot + 1))
        self._out('endobj')

        self._newobj()
        self._out('<</Type/Sig/SubFilter/adbe.pkcs7.detached/Location(%(location)s)/M(D:%(signingdate)s)' % self.pkcs11config)
        self._out(
            '/ByteRange [0000000000 0000000000 0000000000 0000000000]/Filter/Adobe.PPKLite/Reason(%(reason)s)/ContactInfo(%(contact)s)' % self.pkcs11config)
        self.buffer += '/Contents <'
        self.buffer += self.pkcs11zeros
        self.buffer += '>>>\n'
        self._out('endobj')

    def pkcs11_sign(self):
        sbr = 'SIGNER 0 R'
        dbr = '%-6d 0 R' % self.pkcs11annot
        self.buffer = self.buffer.replace(sbr, dbr, 2)

        buffer = self.buffer.encode('latin1')
        zeros = self.pkcs11zeros.encode('latin1')

        pdfbr1 = buffer.find(zeros)
        pdfbr2 = pdfbr1 + len(zeros)
        br = (0, pdfbr1 - 1, pdfbr2 + 1, len(buffer) - pdfbr2 - 1)
        sbr = b'[0000000000 0000000000 0000000000 0000000000]'
        dbr = b'[%010d %010d %010d %010d]' % br
        buffer = buffer.replace(sbr, dbr, 1)

        b1 = buffer[:br[1]]
        b2 = buffer[br[2]:]
        md = getattr(hashlib, self.pkcs11algomd)()
        md.update(b1)
        md.update(b2)
        signed_md = md.digest()

        contents = signer.sign(None, self.pkcs11key, self.pkcs11cert, self.pkcs11certs, self.pkcs11algomd, True,
                               signed_md)
        contents = self.pkcs11_aligned(contents)

        buffer = buffer.replace(zeros, contents.encode('latin1'), 1)

        self.buffer = buffer.decode('latin1')
