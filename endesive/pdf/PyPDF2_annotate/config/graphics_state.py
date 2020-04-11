# -*- coding: utf-8 -*-
"""
    GraphicsState
    ~~~~~~~~~~~~~
    Configuration for an annotation's graphics state.

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import attr
from ..pdfrw import PdfDict, PdfName

from ..config.constants import ALLOWED_LINE_CAPS
from ..config.constants import ALLOWED_LINE_JOINS
from ..util.validation import between
from ..util.validation import Enum
from ..util.validation import Field
from ..util.validation import Number
from ..util.validation import positive
from ..util.validation import validate_dash_array


NAME_TO_PDF_ATTR = {
    "line_width": "LW",
    "line_cap": "LC",
    "line_join": "LJ",
    "miter_limit": "ML",
    "dash_array": "D",
    "stroke_transparency": "CA",
    "fill_transparency": "ca",
}


@attr.s
class GraphicsState(object):
    """External graphics state config object, that can be used with explicit
    content streams to control annotation appearance.

    Some of these values can also be specified by their own operators in the
    content stream. For example, the line_width property can also be specified
    by the StrokeWidth (w) content stream operator.

    See the full PDF spec for constraints on and descriptions of these values.
    There are a lot more graphics state options, but they are highly technical
    and beyond the scope of this library.
    """

    line_width = Number(default=None, validator=positive)
    line_cap = Enum(ALLOWED_LINE_CAPS, default=None)
    line_join = Enum(ALLOWED_LINE_JOINS, default=None)
    miter_limit = Number(default=None)
    dash_array = Field(list, validator=validate_dash_array, default=None)
    stroke_transparency = Number(default=None, validator=between(0, 1))
    fill_transparency = Number(default=None, validator=between(0, 1))

    def as_pdf_dict(self):
        pdf_dict = PdfDict(Type=PdfName("ExtGState"))
        for attr_name, attr_value in self.__dict__.items():
            if attr_value is not None:
                pdf_name = NAME_TO_PDF_ATTR[attr_name]
                pdf_dict[PdfName(pdf_name)] = attr_value
        return pdf_dict

    def has_content(self):
        """Returns True if any of the attributes is non-null."""
        return any(value is not None for value in self.__dict__.values())
