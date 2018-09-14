#!/usr/bin/env vpython3
# *-* coding: utf-8 *-*
import sys


def show(fname):
    print('*' * 20, fname)
    data = open(fname, 'rb').read()
    s = data.find(b'xref')
    while s > 0:
        e = data.find(b'trailer', s) - 1
        offsets = data[s:e].split(b'\n')
        print(offsets)
        if 1:
            for offset in offsets[2:]:
                offset = offset.split()
                if len(offset) != 3:
                    continue
                offset = int(offset[0], 10)
                sdata = data[offset:offset + 32].split(b'\n')[0]
                print(offset, '->', sdata)
        s = data.find(b'%%EOF', e)
        print('%%EOF at', s)
        s = data.find(b'xref', s)

    s = data.find(b'/ByteRange')
    if s > 0:
        start = data.find(b'[', s) + 1
        end = data.find(b']', s)
        byterange = [int(i, 10) for i in data[start:end].split()]
        print('/ByteRange', ':', s, start, end, ':', byterange)
        print('/Contents', ':', chr(data[byterange[1]]), '...', chr(data[byterange[2] - 1]))


def main():
    show(sys.argv[1])


main()
