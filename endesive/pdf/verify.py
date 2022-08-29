# *-* coding: utf-8 *-*
from endesive import verifier


def verify(pdfdata, certs=None):
    results = []
    n = pdfdata.find(b"/ByteRange")
    while n != -1:
        start = pdfdata.find(b"[", n)
        stop = pdfdata.find(b"]", start)
        assert n != -1 and start != -1 and stop != -1
        br = [int(i, 10) for i in pdfdata[start + 1 : stop].split()]
        contents = pdfdata[br[0] + br[1] + 1 : br[2] - 1]
        bcontents = bytes.fromhex(contents.decode("utf8"))
        data1 = pdfdata[br[0] : br[0] + br[1]]
        data2 = pdfdata[br[2] : br[2] + br[3]]
        signedData = data1 + data2

        result = verifier.verify(bcontents, signedData, certs)
        results.append(result)
        n = pdfdata.find(b"/ByteRange", br[2] + br[3])
    return results