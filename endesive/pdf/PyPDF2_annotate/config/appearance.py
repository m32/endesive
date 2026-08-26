# -*- coding: utf-8 -*-
"""
    Appearance Config
    ~~~~~~~~~~~~~~~~~
    Configuration for an annotation's appearance.

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import attr

from ..graphics import (
    ContentStream,
    FillColor,
    GraphicsState as CSGraphicsState,
    Stroke,
    StrokeAndFill,
    StrokeColor,
    StrokeWidth,
)
from ..util.validation import (
    Boolean,
    Color,
    Enum,
    Field,
    Number,
    String,
    between,
    positive,
    validate_dash_array,
)
from .constants import (
    ALLOWED_ALIGNS,
    ALLOWED_BASELINES,
    ALLOWED_LINE_CAPS,
    ALLOWED_LINE_JOINS,
    BLACK,
    DEFAULT_BORDER_STYLE,
    DEFAULT_CONTENT,
    DEFAULT_FONT_SIZE,
    DEFAULT_LINE_SPACING,
    DEFAULT_STROKE_WIDTH,
    GRAPHICS_STATE_NAME,
    TEXT_ALIGN_LEFT,
    TEXT_BASELINE_MIDDLE,
)
from .graphics_state import GraphicsState


def is_transparent(color):
    # E.g. a soothing gray: [0, 0, 0, 0.5]
    if color is None:
        return False
    return len(color) == 4 and color[-1] < 1


@attr.s
class Appearance(object):
    # Stroke attributes
    stroke_color = Color(default=BLACK)
    stroke_width = Number(default=DEFAULT_STROKE_WIDTH, validator=positive)
    border_style = String(default=DEFAULT_BORDER_STYLE)
    dash_array = Field(list, default=None, validator=validate_dash_array)
    line_cap = Enum(ALLOWED_LINE_CAPS, default=None)
    line_join = Enum(ALLOWED_LINE_JOINS, default=None)
    miter_limit = Number(default=None, validator=positive)
    stroke_transparency = Number(default=None, validator=between(0, 1))

    # Fill attributes
    fill = Color(default=None)
    fill_transparency = Number(default=None, validator=between(0, 1))

    # Text attributes
    content = String(default=DEFAULT_CONTENT)
    font_size = Number(default=DEFAULT_FONT_SIZE, validator=positive)
    text_align = Enum(ALLOWED_ALIGNS, default=TEXT_ALIGN_LEFT)
    text_baseline = Enum(ALLOWED_BASELINES, default=TEXT_BASELINE_MIDDLE)
    line_spacing = Number(default=DEFAULT_LINE_SPACING, validator=positive)
    wrap_text = Boolean(default=True)

    # Image attributes
    image = String(default=None)

    # Advanced attributes
    appearance_stream = Field(ContentStream, default=None)
    xobjects = Field(dict, default=None)
    graphics_states = Field(dict, default=None)
    fonts = Field(dict, default=None)

    def copy(self, **kwargs):
        A = Appearance(**kwargs)
        for k, v in self.__dict__.items():
            if k not in kwargs:
                setattr(A, k, v)
        return A

    def _get_stroke_transparency(self):
        stroke_transparency = None
        if is_transparent(self.stroke_color):
            stroke_transparency = self.stroke_color[-1]
        if self.stroke_transparency is not None:
            stroke_transparency = self.stroke_transparency
        return stroke_transparency

    def _get_fill_transparency(self):
        fill_transparency = None
        if is_transparent(self.fill):
            fill_transparency = self.fill[-1]
        if self.fill_transparency is not None:
            fill_transparency = self.fill_transparency
        return fill_transparency

    def get_graphics_state(self):
        """Return a GraphicsState config from the appearance's graphics-state-
        applicable params.

        :returns GraphicsState:
        """
        return GraphicsState(
            dash_array=self.dash_array,
            line_cap=self.line_cap,
            line_join=self.line_join,
            miter_limit=self.miter_limit,
            stroke_transparency=self._get_stroke_transparency(),
            fill_transparency=self._get_fill_transparency(),
        )


def set_appearance_state(stream, A):
    """Update the graphics command stream to reflect appearance properties.

    :param ContentStream stream: current content stream
    :param Appearance A: appearance object
    """
    # Add in the `gs` command, which will execute the named graphics state from
    # the Resources dict, and set CA and/or ca values. The annotations
    # themselves will need to ensure that the proper ExtGState object is
    # present in the Resources dict.
    graphics_state = A.get_graphics_state()
    if graphics_state.has_content():
        stream.add(CSGraphicsState(GRAPHICS_STATE_NAME))

    stream.extend([
        StrokeColor(*A.stroke_color[:3]),
        StrokeWidth(A.stroke_width),
    ])

    # TODO support more color spaces - CMYK and GrayScale
    if A.fill is not None:
        stream.add(FillColor(*A.fill[:3]))


def stroke_or_fill(stream, A):
    if A.fill is not None:
        stream.add(StrokeAndFill())
    else:
        stream.add(Stroke())
