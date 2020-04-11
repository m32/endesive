#!/usr/bin/env vpython3
class Main:
    def __init__(self, fname):
        with open(fname, "rb") as fi:
            self.data = fi.read()
        self.xrefs = []

    def find(self, s, start=0):
        i = self.data.find(s, start)
        if i >= 0:
            i += len(s)
        return i

    def readline(self, start):
        i1 = i0 = start
        while self.data[i1] not in b'\r\n':
            i1 += 1
        n = i1
        while self.data[n] in b'\r\n':
            n += 1
        return self.data[i0:i1].strip(), n

    def xref(self):
        xref = 0
        while True:
            xref = self.find(b'\nxref\n', xref)
            if xref < 0:
                break
            n = xref
            while True:
                line, n = self.readline(n)
                line = line.split()
                try:
                    assert len(line) == 2
                    off, cnt = int(line[0]), int(line[1])
                except:
                    break
                for i in range(cnt):
                    line, n = self.readline(n)
                    line = line.split()
                    if line[-1] == b'n':
                        offset = int(line[0])
                        line1 = self.readline(offset)[0].split()
                        try:
                            assert len(line1) == 3 and int(line1[0]) == off + i
                        except:
                            print('bad xref:', line, line1, 'off:', off+i, len(line1))
                        print(line1, off+i, offset)
                        #self.xref.append(
    def byterange(self):
        start = self.find(b'/ByteRange')
        i0 = self.find(b'[', start)
        i1 = self.find(b']', start)
        line = self.data[i0:i1-1]
        line = line.split()
        br = [int(line[0]), int(line[1]), int(line[2]), int(line[3])]
        print(br, [hex(i) for i in br])
        c = self.data[br[1]]
        print('[{:06x}]: {:d} {:02x}'.format(br[1], c, c))
        c = self.data[br[2]]
        print('[{:06x}]: {:d} {:02x}'.format(br[2], c, c))
        print(len(self.data), br[2]+br[3])
        contents = self.data[br[0] + br[1] + 1 : br[2] - 1]
        print('[contents]:', len(contents))

    def main(self):
        self.xref()
        self.byterange()

for fname in (
    #"pdf-certum.pdf",
    #"pdf-acrobat.pdf",
    'pdf-signed-java.pdf',
    'pdf-signed-pypdf.pdf',
    'pdf-encrypted-signed-java.pdf',
    'pdf-encrypted-signed-pypdf.pdf',
):
    print('*'*20, fname)
    try:
        cls = Main(fname)
    except IOError:
        continue
    cls.main()
