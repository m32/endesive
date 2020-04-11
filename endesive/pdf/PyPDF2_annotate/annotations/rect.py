# -*- coding: utf-8 -*-
"""
    Rectangular Annotations
    ~~~~~~~~~~~~~~~~~~~~~~~
    Annotations defined by a width and a height: Square, Circle

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
from .base import Annotation
from .base import make_border_dict
from ..pdfrw import PdfArray, PdfName
from ..config.appearance import set_appearance_state
from ..config.appearance import stroke_or_fill
from ..graphics import Bezier
from ..graphics import Close
from ..graphics import ContentStream
from ..graphics import Line
from ..graphics import Move
from ..graphics import quadratic_to_cubic_bezier
from ..graphics import Rect
from ..graphics import Restore
from ..graphics import Save


class RectAnnotation(Annotation):
    """Abstract annotation that defines its location on the document with a
    width and a height.
    """

    def make_rect(self):
        stroke_width = self._appearance.stroke_width
        L = self._location
        return [
            L.x1 - stroke_width,
            L.y1 - stroke_width,
            L.x2 + stroke_width,
            L.y2 + stroke_width,
        ]

    def add_additional_pdf_object_data(self, obj):
        A = self._appearance
        obj[PdfName("BS")] = make_border_dict(A)
        obj[PdfName("C")] = A.stroke_color
        if A.fill:
            obj[PdfName("IC")] = A.fill
        padding = A.stroke_width / 2.0
        obj[PdfName("RD")] = PdfArray([padding, padding, padding, padding])


class Square(RectAnnotation):
    subtype = "Square"

    def make_appearance_stream(self):
        L = self._location
        A = self._appearance
        stream = ContentStream([Save()])

        set_appearance_state(stream, A)
        stream.add(Rect(L.x1, L.y1, L.x2 - L.x1, L.y2 - L.y1))
        stroke_or_fill(stream, A)
        stream.add(Restore())

        # TODO dash array
        return stream


def add_rounded_rectangle(stream, x, y, width, height, rx, ry):
    """Creates a rounded rectangle and adds it to the content stream.

    :param ContentStream stream:
    :param float x1:
    :param float y1:
    :param float width:
    :param float height:
    :param float rx: x radius of the rounded corners
    :param float ry: y radius of the rounded corners
    """
    stream.add(Move(x + rx, y))
    stream.add(Line(x + width - rx, y))
    stream.add(
        quadratic_to_cubic_bezier(
            start_x=(x + width - rx),
            start_y=y,
            control_x=(x + width),
            control_y=y,
            end_x=(x + width),
            end_y=(y + ry),
        )
    )
    stream.add(Line(x + width, y + height - ry))
    stream.add(
        quadratic_to_cubic_bezier(
            start_x=(x + width),
            start_y=(y + height - ry),
            control_x=(x + width),
            control_y=(y + height),
            end_x=(x + width - rx),
            end_y=(y + height),
        )
    )
    stream.add(Line(x + rx, y + height))
    stream.add(
        quadratic_to_cubic_bezier(
            start_x=(x + rx),
            start_y=(y + height),
            control_x=x,
            control_y=(y + height),
            end_x=x,
            end_y=(y + height - ry),
        )
    )
    stream.add(Line(x, y + ry))
    stream.add(
        quadratic_to_cubic_bezier(
            start_x=x,
            start_y=(y + ry),
            control_x=x,
            control_y=y,
            end_x=(x + rx),
            end_y=y,
        )
    )
    stream.add(Close())


def add_bezier_circle(stream, x1, y1, x2, y2):
    """Create a circle from four bezier curves and add it to the content stream,
    since PDF graphics is missing an ellipse primitive.

    :param ContentStream stream:
    :param float x1:
    :param float y1:
    :param float x2:
    :param float y2:
    """
    left_x = x1
    right_x = x2
    bottom_x = left_x + (right_x - left_x) / 2.0
    top_x = bottom_x

    bottom_y = y1
    top_y = y2
    left_y = bottom_y + (top_y - bottom_y) / 2.0
    right_y = left_y

    cp_offset = 0.552284749831
    # Move to the bottom of the circle, then four curves around.
    # https://stackoverflow.com/questions/1734745/how-to-create-circle-with-b%C3%A9zier-curves
    stream.add(Move(bottom_x, bottom_y))
    stream.add(
        Bezier(
            bottom_x + (right_x - bottom_x) * cp_offset,
            bottom_y,
            right_x,
            right_y - (right_y - bottom_y) * cp_offset,
            right_x,
            right_y,
        )
    )
    stream.add(
        Bezier(
            right_x,
            right_y + (top_y - right_y) * cp_offset,
            top_x + (right_x - top_x) * cp_offset,
            top_y,
            top_x,
            top_y,
        )
    )
    stream.add(
        Bezier(
            top_x - (top_x - left_x) * cp_offset,
            top_y,
            left_x,
            left_y + (top_y - left_y) * cp_offset,
            left_x,
            left_y,
        )
    )
    stream.add(
        Bezier(
            left_x,
            left_y - (left_y - bottom_y) * cp_offset,
            bottom_x - (bottom_x - left_x) * cp_offset,
            bottom_y,
            bottom_x,
            bottom_y,
        )
    )
    stream.add(Close())


class Circle(RectAnnotation):
    """Circles and Squares are basically the same PDF annotation but with
    different content streams.
    """

    subtype = "Circle"

    def make_appearance_stream(self):
        L = self._location
        A = self._appearance

        stream = ContentStream([Save()])
        set_appearance_state(stream, A)
        add_bezier_circle(stream, L.x1, L.y1, L.x2, L.y2)
        stroke_or_fill(stream, A)
        stream.add(Restore())

        return stream
