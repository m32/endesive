# -*- coding: utf-8 -*-
"""
    Text Annotations
    ~~~~~~~~~~~~~~~~
    The FreeText annotation

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import os.path

from ..pdfrw import PdfDict, PdfName, PdfString, PdfArray, IndirectPdfDict

from .base import _make_border_dict
from .base import Annotation
from ..config.constants import DEFAULT_BASE_FONT
from ..config.constants import GRAPHICS_STATE_NAME
from ..config.constants import PDF_ANNOTATOR_FONT
from ..graphics import BeginText
from ..graphics import ContentStream
from ..graphics import EndText
from ..graphics import FillColor
from ..graphics import Font
from ..graphics import GraphicsState as CSGraphicsState
from ..graphics import Restore
from ..graphics import Save
from ..graphics import Text
from ..graphics import TextMatrix
from ..util.geometry import translate
from ..util.text import get_wrapped_lines
from ..util.true_type_font import get_true_type_font


HELVETICA_PATH = os.path.join(os.path.dirname(__file__), "..", "fonts", "Helvetica.ttf")


class FreeText(Annotation):
    """FreeText annotation. Right now, we only support writing text in the
    Helvetica font. Dealing with fonts is tricky business, so we'll leave that
    for later.
    """

    subtype = "FreeText"

    def make_rect(self):
        L = self._location
        return [L.x1, L.y1, L.x2, L.y2]

    def make_default_appearance(self):
        """Returns a DA string for the text object, e.g. '1 0 0 rg /Helv 12 Tf'
        """
        A = self._appearance
        stream = ContentStream(
            [FillColor(*A.fill[:3]), Font(PDF_ANNOTATOR_FONT, A.font_size)]
        )
        return stream.resolve()

    def add_additional_pdf_object_data(self, obj):
        obj[PdfName("Contents")] = self._appearance.content
        obj[PdfName("DA")] = self.make_default_appearance()
        obj[PdfName("C")] = []
        # TODO allow setting border on free text boxes
        obj[PdfName("BS")] = _make_border_dict(width=0, style="S")
        # TODO DS is required to have BB not redraw the annotation in their own
        # style when you edit it.

    @staticmethod
    def make_font_file_object(tt_font):
        """Make an embedded font object from the true type font itself.

        :param TrueTypeFont tt_font: Our utility class used to parse and calculate font metrics
        from a true type font.
        :returns PdfDict: font file PdfDict object stream.
        """
        # TODO: make subset font here
        with open(tt_font.ttfPath, "rb") as font_file:
            data = font_file.read()

        # Let's let pdfrw handle compressing streams
        return IndirectPdfDict(stream=data.decode("Latin-1"))

    @staticmethod
    def make_to_unicode_object():
        """Make a toUnicode object which allows the PDF reader to derive content from the PDF
        with the CIDFont embedded.  This map converts from CIDs to Unicode code points.

        :returns PdfDict: toUnicode CMAP PdfDict object.
        """
        # See section 9.10.3 ToUnicode CMaps of PDF 1.6 Spec
        # TODO: For now we put an empty mapping in.
        return IndirectPdfDict(
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

    @staticmethod
    def make_cid_to_gid_map_object(tt_font):
        """Make a CID to GID map that is used to map character ids to glyph ids in the font.

        :param TrueTypeFont tt_font: Our utility class used to parse and calculate font metrics
        from a true type font.
        :returns PdfDict: CIDtoGID PdfDict object.
        """
        # Let's make this as large as possibly addressable for now, it will compress nicely.
        mapping_size = 256 * 256
        cid_to_gid_map = ["\x00"] * mapping_size * 2

        for cc, glyph_name in tt_font.metrics.cmap.items():
            # TODO: What is the expectation here since PDF only supports two bytes lookups?
            if cc >= mapping_size:
                continue
            glyph_id = tt_font.get_glyph_id(glyph_name)
            cid_to_gid_map[cc * 2] = chr(glyph_id >> 8)
            cid_to_gid_map[cc * 2 + 1] = chr(glyph_id & 0xFF)
        cid_to_gid_map = "".join(cid_to_gid_map)

        # Let's let pdfrw handle the compressing of streams
        return IndirectPdfDict(stream=cid_to_gid_map)

    @staticmethod
    def make_font_descriptor_object(tt_font):
        """Make a Font Descriptor object containing some calculated metrics
        for the font.

        :param TrueTypeFont tt_font: Our utility class used to parse and calculate font metrics
        from a true type font.
        :returns PdfDict: Font Descriptor PdfDict object.
        """
        return IndirectPdfDict(
            Type=PdfName("FontDescriptor"),
            FontName=PdfName(tt_font.fontName),
            Flags=tt_font.metrics.flags,
            FontBBox=tt_font.metrics.bbox,
            ItalicAngle=int(tt_font.metrics.italicAngle),
            Ascent=int(round(tt_font.metrics.ascent, 0)),
            Descent=int(round(tt_font.metrics.descent, 0)),
            CapHeight=int(round(tt_font.metrics.capHeight, 0)),
            StemV=int(round(tt_font.metrics.stemV, 0)),
            MissingWidth=int(round(tt_font.metrics.defaultWidth, 0)),
            FontFile2=FreeText.make_font_file_object(tt_font),
        )

    @staticmethod
    def make_cid_system_info_object():
        """Make a CID System Info object.

        :returns PdfDict: CID System Info PdfDict object.
        """
        return IndirectPdfDict(
            Registry=PdfString("Adobe"), Ordering=PdfString("UCS"), Supplement=0
        )

    @staticmethod
    def make_cid_font_object(tt_font):
        """Make a CID Type 2 font object for including as a descendant of a composite
        Type 0 font object.

        :param TrueTypeFont tt_font: Our utility class used to parse and calculate font metrics
        from a true type font.
        :returns PdfDict: CID Font Type 2 PdfDict object.
        """
        return IndirectPdfDict(
            Type=PdfName("Font"),
            Subtype=PdfName("CIDFontType2"),
            BaseFont=PdfName(tt_font.fontName),
            CIDSystemInfo=FreeText.make_cid_system_info_object(),
            FontDescriptor=FreeText.make_font_descriptor_object(tt_font),
            DW=int(round(tt_font.metrics.defaultWidth, 0)),
            Widths=PdfArray(tt_font.metrics.widths),
            CIDToGIDMap=FreeText.make_cid_to_gid_map_object(tt_font),
        )

    @staticmethod
    def make_composite_font_object(font_file_path):
        """Make a PDF Type0 composite font object for embedding in the annotation's
        Resources dict.

        :param str font_file_path: The path and filename to the true type font we want to embed.
        :returns PdfDict: Resources PdfDict object, ready to be included in the
            Resources 'Font' subdictionary.
        """
        # TODO: Get font name from font program itself
        tt_font = get_true_type_font(font_file_path, DEFAULT_BASE_FONT)

        return IndirectPdfDict(
            Type=PdfName("Font"),
            Subtype=PdfName("Type0"),
            BaseFont=PdfName(tt_font.fontName),
            Encoding=PdfName("Identity-H"),
            DescendantFonts=PdfArray([FreeText.make_cid_font_object(tt_font)]),
            ToUnicode=FreeText.make_to_unicode_object(),
        )

    @staticmethod
    def make_font_object():
        """Make a PDF Type1 font object for embedding in the annotation's
        Resources dict. Only Helvetica is supported as a base font.

        :returns PdfDict: Resources PdfDict object, ready to be included in the
            Resources 'Font' subdictionary.
        """
        return PdfDict(
            Type=PdfName("Font"),
            Subtype=PdfName("Type1"),
            BaseFont=PdfName(DEFAULT_BASE_FONT),
            Encoding=PdfName("WinAnsiEncoding"),
        )

    def add_additional_resources(self, resources):
        font_dict = PdfDict()
        font_dict[PdfName(PDF_ANNOTATOR_FONT)] = self.make_font_object()
        resources[PdfName("Font")] = font_dict

    def make_appearance_stream(self):
        A = self._appearance
        L = self._location

        stream = ContentStream(
            [
                Save(),
                BeginText(),
                FillColor(*A.fill[:3]),
                Font(PDF_ANNOTATOR_FONT, A.font_size),
            ]
        )

        graphics_state = A.get_graphics_state()
        if graphics_state.has_content():
            stream.add(CSGraphicsState(GRAPHICS_STATE_NAME))

        # Actually draw the text inside the rectangle
        stream.extend(
            get_text_commands(
                L.x1,
                L.y1,
                L.x2,
                L.y2,
                text=A.content,
                font_size=A.font_size,
                wrap_text=A.wrap_text,
                align=A.text_align,
                baseline=A.text_baseline,
                line_spacing=A.line_spacing,
            )
        )
        stream.extend([EndText(), Restore()])

        return stream


def get_text_commands(
    x1, y1, x2, y2, text, font_size, wrap_text, align, baseline, line_spacing
):
    """Return the graphics stream commands necessary to render a free text
    annotation, given the various parameters.

    Text is optionally wrapped, then arranged according to align (horizontal
    alignment), and baseline (vertical alignment).

    :param number x1: bounding box lower left x
    :param number y1: bounding box lower left y
    :param number x2: bounding box upper right x
    :param number y2: bounding box upper right y
    :param str text: text to add to annotation
    :param number font_size: font size
    :param bool wrap_text: whether to wrap the text
    :param str align: 'left'|'center'|'right'
    :param str baseline: 'top'|'middle'|'bottom'
    :param number line_spacing: multiplier to determine line spacing
    """
    font = get_true_type_font(
        path=HELVETICA_PATH, font_name=DEFAULT_BASE_FONT, font_size=font_size
    )

    lines = (
        get_wrapped_lines(text=text, measure=font.measure_text, max_length=x2 - x1)
        if wrap_text
        else [text]
    )
    # Line breaking cares about the whitespace in the string, but for the
    # purposes of laying out the broken lines, we want to measure the lines
    # without trailing/leading whitespace.
    lines = [line.strip() for line in lines]
    y_coords = _get_vertical_coordinates(
        lines, y1, y2, font_size, line_spacing, baseline
    )
    xs = _get_horizontal_coordinates(lines, x1, x2, font.measure_text, align)
    commands = []
    for line, x, y in zip(lines, xs, y_coords):
        commands.extend([TextMatrix(translate(x, y)), Text(line)])
    return commands


def _get_vertical_coordinates(lines, y1, y2, font_size, line_spacing, baseline):
    """Calculate vertical coordinates for all the lines at once, honoring the
    text baseline property.
    """
    line_spacing = font_size * line_spacing
    if baseline == "top":
        first_y = y2 - line_spacing
    elif baseline == "middle":
        midpoint = (y2 + y1) / 2.0
        # For the first line of vertically centered text, go up half the # of
        # lines, then go back down half the font size.
        first_y = (
            midpoint
            - (line_spacing - font_size)
            + (((len(lines) - 1) / 2.0) * line_spacing)
        )
    else:  # bottom
        first_y = y1 + (line_spacing - font_size) + (line_spacing * (len(lines) - 1))
    return [first_y - (i * line_spacing) for i in range(len(lines))]


def _get_horizontal_coordinates(lines, x1, x2, measure, align):
    # NOTE: this padding is to keep text annotations as they are from cutting
    # off text at the edges in certain conditions. The annotation rectangle
    # and how PDFs draw text needs to be revisited, as this padding shouldn't
    # be necessary.
    PADDING = 1
    if align == "left":
        return [x1 + PADDING for _ in range(len(lines))]
    elif align == "center":
        widths = [measure(line) for line in lines]
        max_width = x2 - x1
        return [x1 + ((max_width - width) / 2.0) - PADDING for width in widths]
    else:  # right
        widths = [measure(line) for line in lines]
        max_width = x2 - x1
        return [x1 + (max_width - width) - PADDING for width in widths]
