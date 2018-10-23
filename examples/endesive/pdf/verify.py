# *-* coding: utf-8 *-*
from endesive import verifier


def verify(pdfdata, certs=None):
    n = pdfdata.find(b'/ByteRange')
    start = pdfdata.find(b'[', n)
    stop = pdfdata.find(b']', start)
    assert n != -1 and start != -1 and stop != -1
    br = [int(i, 10) for i in pdfdata[start + 1:stop].split()]
    contents = pdfdata[br[0] + br[1] + 1:br[2] - 1]
    data = []
    for i in range(0, len(contents), 2):
        data.append(int(contents[i:i + 2], 16))
    bcontents = bytes(data)
    data1 = pdfdata[br[0]: br[0] + br[1]]
    data2 = pdfdata[br[2]: br[2] + br[3]]
    signedData = data1 + data2

    return verifier.verify(bcontents, signedData, certs)
