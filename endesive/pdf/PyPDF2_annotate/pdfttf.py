import os
import re
import zlib

from ..fpdf.ttfonts import TTFontFile
from .pdfrw import PdfDict, PdfName, PdfString, PdfArray, IndirectPdfDict


class TTFFont:
    def __init__(self, ttffilename):
        self.size = 12
        self.font = None

        ttf = TTFontFile()
        ttf.getMetrics(ttffilename)
        desc = {
            "Ascent": int(round(ttf.ascent, 0)),
            "Descent": int(round(ttf.descent, 0)),
            "CapHeight": int(round(ttf.capHeight, 0)),
            "Flags": ttf.flags,
            "FontBBox": (
                int(round(ttf.bbox[0], 0)),
                int(round(ttf.bbox[1], 0)),
                int(round(ttf.bbox[2], 0)),
                int(round(ttf.bbox[3], 0)),
            ),
            "ItalicAngle": int(ttf.italicAngle),
            "StemV": int(round(ttf.stemV, 0)),
            "MissingWidth": int(round(ttf.defaultWidth, 0)),
        }
        font_dict = {
            "type": "TTF",
            "name": re.sub("[ ()]", "", ttf.fullName),
            "desc": desc,
            "up": round(ttf.underlinePosition),
            "ut": round(ttf.underlineThickness),
            "cw": ttf.charWidths,
            "ttffile": ttffilename,
            # "fontkey": fontkey,
            "originalsize": os.stat(ttffilename).st_size,
            "subset": set(range(0, 32)),
        }
        self.font = font_dict

    def font_widths(self, font, maxUni):
        rangeid = 0
        range_ = {}
        range_interval = {}
        prevcid = -2
        prevwidth = -1
        interval = False
        startcid = 1
        cwlen = maxUni + 1

        # for each character
        for cid in range(startcid, cwlen):
            if font["cw"][cid] == 0:
                continue
            width = font["cw"][cid]
            if width == 65535:
                width = 0
            if cid > 255 and (cid not in font["subset"]) or not cid:  #
                continue
            if "dw" not in font or (font["dw"] and width != font["dw"]):
                if cid == (prevcid + 1):
                    if width == prevwidth:
                        if width == range_[rangeid][0]:
                            range_.setdefault(rangeid, []).append(width)
                        else:
                            range_[rangeid].pop()
                            # new range
                            rangeid = prevcid
                            range_[rangeid] = [prevwidth, width]
                        interval = True
                        range_interval[rangeid] = True
                    else:
                        if interval:
                            # new range
                            rangeid = cid
                            range_[rangeid] = [width]
                        else:
                            range_[rangeid].append(width)
                        interval = False
                else:
                    rangeid = cid
                    range_[rangeid] = [width]
                    interval = False
                prevcid = cid
                prevwidth = width
        prevk = -1
        nextk = -1
        prevint = False
        for k, ws in sorted(range_.items()):
            cws = len(ws)
            if k == nextk and not prevint and (not k in range_interval or cws < 3):
                if k in range_interval:
                    del range_interval[k]
                range_[prevk] = range_[prevk] + range_[k]
                del range_[k]
            else:
                prevk = k
            nextk = k + cws
            if k in range_interval:
                prevint = cws > 3
                del range_interval[k]
                nextk -= 1
            else:
                prevint = False
        w = []
        for k, ws in sorted(range_.items()):
            if len(set(ws)) == 1:
                w.extend((k, k + len(ws) - 1, ws[0]))
            else:
                w.extend((k, ws))
        return w

    def get_font(self):
        font = self.font
        # Font objects
        ttf = TTFontFile()
        fontname = "MPDFAA" + "+" + font["name"]
        subset = font["subset"].difference(set([0]))
        ttfontstream = ttf.makeSubset(font["ttffile"], subset)
        ttfontstream = zlib.compress(ttfontstream)
        codeToGlyph = ttf.codeToGlyph
        ##del codeToGlyph[0]

        # Font file
        FontFile2 = IndirectPdfDict(stream=ttfontstream, Filter=PdfName("FlateDecode"))
        # CIDSystemInfo dictionary
        CIDSystemInfo = IndirectPdfDict(
            Registry=PdfString("Adobe"), Ordering=PdfString("UCS"), Supplement=0
        )

        # Font descriptor
        FontDescriptor = IndirectPdfDict(
            Type=PdfName("FontDescriptor"),
            FontName=PdfName(fontname),
            Flags=(font["desc"]["Flags"] | 4) & ~32,
            FontBBox=font["desc"]["FontBBox"],
            ItalicAngle=font["desc"]["ItalicAngle"],
            Ascent=font["desc"]["Ascent"],
            Descent=font["desc"]["Descent"],
            CapHeight=font["desc"]["CapHeight"],
            StemV=font["desc"]["StemV"],
            MissingWidth=font["desc"]["MissingWidth"],
            FontFile2=FontFile2,
        )

        # Embed CIDToGIDMap
        # A specification of the mapping from CIDs to glyph indices
        cidtogidmap = ["\x00"] * 256 * 256 * 2
        for cc, glyph in codeToGlyph.items():
            cidtogidmap[cc * 2] = chr(glyph >> 8)
            cidtogidmap[cc * 2 + 1] = chr(glyph & 0xFF)
        cidtogidmap = "".join(cidtogidmap)
        # manage binary data as latin1 until PEP461-like function is implemented
        cidtogidmap = cidtogidmap.encode("latin1")
        cidtogidmap = zlib.compress(cidtogidmap)
        CIDToGIDMap = IndirectPdfDict(stream=cidtogidmap, Filter=PdfName("FlateDecode"))

        # CIDFontType2
        # A CIDFont whose glyph descriptions are based on TrueType font technology
        CIDFontType2 = IndirectPdfDict(
            Type=PdfName("Font"),
            Subtype=PdfName("CIDFontType2"),
            BaseFont=PdfName(fontname),
            CIDSystemInfo=CIDSystemInfo,
            FontDescriptor=FontDescriptor,
            W=PdfArray(self.font_widths(font, ttf.maxUni)),
            CIDToGIDMap=CIDToGIDMap,
        )
        if font["desc"].get("MissingWidth"):
            CIDFontType2[PdfName("DW")] = font["desc"]["MissingWidth"]

        # ToUnicode
        ToUnicode = IndirectPdfDict(
            stream="\n".join(
                (
                    "/CIDInit /ProcSet findresource begin",
                    "12 dict begin",
                    "begincmap",
                    "/CIDSystemInfo",
                    "<</Registry (Adobe)",
                    "/Ordering (UCS)",
                    "/Supplement 0",
                    ">> def",
                    "/CMapName /Adobe-Identity-UCS def",
                    "/CMapType 2 def",
                    "1 begincodespacerange",
                    "<0000> <FFFF>",
                    "endcodespacerange",
                    "1 beginbfrange",
                    "<0000> <FFFF> <0000>",
                    "endbfrange",
                    "endcmap",
                    "CMapName currentdict /CMap defineresource pop",
                    "end",
                    "end",
                )
            )
        )

        # Type0 Font
        # A composite font - a font composed of other fonts, organized hierarchically
        Type0 = IndirectPdfDict(
            Type=PdfName("Font"),
            Subtype=PdfName("Type0"),
            BaseFont=PdfName(fontname),
            Encoding=PdfName("Identity-H"),
            DescendantFonts=PdfArray([CIDFontType2]),
            ToUnicode=ToUnicode,
        )
        return Type0

    def set_size(self, pt):
        self.size = pt

    def set_text(self, text):
        uni = set([ord(c) for c in text])
        self.font["subset"] = self.font["subset"].union(uni)

    def measure_text(self, text):
        "Get width of a string in the current font"
        cw = self.font["cw"]
        w = 0
        l = len(text)
        for char in text:
            char = ord(char)
            if len(cw) > char:
                w += cw[char]  # ord(cw[2*char])<<8 + ord(cw[2*char+1])
            # elif (char>0 and char<128 and isset($cw[chr($char)])) { $w += $cw[chr($char)]; }
            elif self.font["desc"]["MissingWidth"]:
                w += self.font["desc"]["MissingWidth"]
            # elif (isset($this->CurrentFont['MissingWidth'])) { $w += $this->CurrentFont['MissingWidth']; }
            else:
                w += 500
        return w * self.size / 1000.0
