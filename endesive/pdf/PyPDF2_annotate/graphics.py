"""
    Graphics
    ~~~~~~~~~~~~
    Classes for manipulating PDF graphics streams.

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
from __future__ import division

from collections import namedtuple
from functools import total_ordering

from .util.geometry import matrix_multiply
from .util.geometry import transform_point
from .util.geometry import transform_vector

ZERO_TOLERANCE = 0.00000000000001


class ContentStream(object):
    """An abstraction over a PDF content stream, e.g. (draw a green rectangle):
    '0 1 0 rg 3 w 1 1 2 2 re S'.

    This abstraction will allow users to draw more precise annotations, while
    still allowing this library to transform those annotations to be properly
    drawn in PDF user space. For instance, a user could do:

    content_stream = ContentStream([
        StrokeColor(1, 0, 0),
        StrokeWidth(5),
        Move(10, 10),
        Line(20, 20),
        Stroke(),
    ])
    annotator.add_annotation(
        'square',
        location=Location(10, 10, 20, 20, page=0),
        appearance=Appearance(appearance_stream=content_stream),
    )

    This would draw a "square" annotation as a line, which is kind of silly,
    but it shows the flexibility for the user to draw more complex annotations.
    Behind the scenes, the pdf-annotator library transforms the Move and Line
    operations to be properly placed in PDF user space.
    """

    def __init__(self, commands=None):
        self.commands = commands or []

    def __eq__(self, other):
        if not isinstance(other, ContentStream):
            return False

        return self.resolve() == other.resolve()

    def add(self, command):
        self.commands.append(command)

    def extend(self, commands):
        self.commands.extend(commands)

    def transform(self, transform):
        return ContentStream([
            command.transform(transform) for command in self.commands
        ])

    def resolve(self):
        return ' '.join(
            command.resolve() for command in self.commands
        )

    @staticmethod
    def join(stream1, stream2):
        """Combine two content streams."""
        return ContentStream(stream1.commands + stream2.commands)


@total_ordering
class BaseCommand(object):
    COMMAND = ''
    NUM_ARGS = 0

    def __eq__(self, other):
        if self.__class__ is not other.__class__:
            return False

        return self.resolve() == other.resolve()

    def __ne__(self, other):
        # yes you really have to define this
        return not self.__eq__(other)

    def __lt__(self, other):
        raise TypeError(
            'Comparison not supported between instances of {} and {}'.format(
                self.__class__.__name__,
                other.__class__.__name__,
            ),
        )

    def transform(self, t):
        return self

    def resolve(self):
        return self.COMMAND

    @classmethod
    def _get_tokens(cls, idx, tokens):
        return tokens[idx-cls.NUM_ARGS:idx]

    @classmethod
    def from_tokens(cls, idx, tokens):
        return cls(*cls._get_tokens(idx, tokens))


class TupleCommand(type):
    def __new__(cls, name, parents, attrs):
        namedtuple_klass = namedtuple(name + '_namedtuple', attrs['ARGS'])

        if 'NUM_ARGS' not in attrs:
            attrs['NUM_ARGS'] = len(attrs['ARGS'])

        attrs.pop('ARGS')

        # don't put object at beginning of MRO
        if parents == (object,):
                parents = ()

        new_parents = (*parents, BaseCommand, namedtuple_klass)

        return super(TupleCommand, cls).__new__(cls, name, new_parents, attrs)

    def __init__(cls, name, parents, attrs):
        if cls.resolve is BaseCommand.resolve:
            def resolve(self):
                return ' '.join([*self] + [self.COMMAND])

            setattr(cls, 'resolve', resolve)


class FloatTupleCommand(TupleCommand):
    def __init__(cls, name, parents, attrs):
        if cls.resolve is BaseCommand.resolve:
            def resolve(self):
                return ' '.join([format_number(n) for n in self] + [self.COMMAND])

            setattr(cls, 'resolve', resolve)

        @classmethod
        def from_tokens(cls, idx, tokens):
            return cls(*map(float, cls._get_tokens(idx, tokens)))

        setattr(cls, 'from_tokens', from_tokens)


class StrokeColor(metaclass=FloatTupleCommand):
    COMMAND = 'RG'
    ARGS = ['r', 'g', 'b']


class StrokeWidth(metaclass=FloatTupleCommand):
    COMMAND = 'w'
    ARGS = ['width']


class FillColor(metaclass=FloatTupleCommand):
    COMMAND = 'rg'
    ARGS = ['r', 'g', 'b']


class BeginText(BaseCommand):
    COMMAND = 'BT'


class EndText(BaseCommand):
    COMMAND = 'ET'


class Stroke(BaseCommand):
    COMMAND = 'S'


class CloseAndStroke(BaseCommand):
    COMMAND = 's'


class StrokeAndFill(BaseCommand):
    COMMAND = 'B'


class StrokeAndFillEvenOdd(BaseCommand):
    COMMAND = 'B*'


class Fill(BaseCommand):
    COMMAND = 'f'


class ReadOnlyFill(BaseCommand):
    # PDF reading should accept F as equivalent to f, but only write f.
    # - Table 60 in PDF spec.
    COMMAND = 'F'

    def resolve(self):
        return Fill.COMMAND


class FillEvenOdd(BaseCommand):
    COMMAND = 'f*'


class CloseFillAndStroke(BaseCommand):
    # equivalent to h B
    COMMAND = 'b'


class CloseFillAndStrokeEvenOdd(BaseCommand):
    # equivalent to h B*
    COMMAND = 'b*'


class EndPath(BaseCommand):
    # End path without filling or stroking; used for clipping paths.
    COMMAND = 'n'


class Save(BaseCommand):
    COMMAND = 'q'


class Restore(BaseCommand):
    COMMAND = 'Q'


class Close(BaseCommand):
    COMMAND = 'h'


class Font(metaclass=TupleCommand):
    COMMAND = 'Tf'
    ARGS = ['font', 'font_size']

    def resolve(self):
        return '/{} {} {}'.format(
            self.font,
            format_number(self.font_size),
            self.COMMAND,
        )

    @classmethod
    def from_tokens(cls, idx, tokens):
        # PDF spec calls font_size a "scale parameter" which implies > 0, but it
        # doesn't declare constraints on it. Unclear if/how we should validate.
        font, font_size = cls._get_tokens(idx, tokens)
        return cls(font, float(font_size))


class Text(metaclass=TupleCommand):
    COMMAND = 'Tj'
    ARGS = ['text']

    def resolve(self):
        return '({}) {}'.format(self.text, self.COMMAND)


class XObject(metaclass=TupleCommand):
    COMMAND = 'Do'
    ARGS = ['name']

    def resolve(self):
        return '/{} {}'.format(self.name, self.COMMAND)


class GraphicsState(metaclass=TupleCommand):
    COMMAND = 'gs'
    ARGS = ['name']

    def resolve(self):
        return '/{} {}'.format(self.name, self.COMMAND)


class Rect(metaclass=FloatTupleCommand):
    COMMAND = 're'
    ARGS = ['x', 'y', 'width', 'height']

    def transform(self, t):
        x, y = transform_point((self.x, self.y), t)
        width, height = transform_vector((self.width, self.height), t)
        return Rect(x, y, width, height)


class Move(metaclass=FloatTupleCommand):
    COMMAND = 'm'
    ARGS = ['x', 'y']

    def transform(self, t):
        x, y = transform_point((self.x, self.y), t)
        return Move(x, y)


class Line(metaclass=FloatTupleCommand):
    COMMAND = 'l'
    ARGS = ['x', 'y']

    def transform(self, t):
        x, y = transform_point((self.x, self.y), t)
        return Line(x, y)


class Bezier(metaclass=FloatTupleCommand):
    """Cubic bezier curve, from the current point to (x3, y3), using (x1, y1)
    and (x2, y2) as control points.
    """
    COMMAND = 'c'
    ARGS = ['x1', 'y1', 'x2', 'y2', 'x3', 'y3']

    def transform(self, t):
        x1, y1 = transform_point((self.x1, self.y1), t)
        x2, y2 = transform_point((self.x2, self.y2), t)
        x3, y3 = transform_point((self.x3, self.y3), t)
        return Bezier(x1, y1, x2, y2, x3, y3)


class BezierV(metaclass=FloatTupleCommand):
    """Cubic bezier curve, from the current point to (x3, y3), using (x2, y2)
    and (x3, y3) as control points.
    """
    COMMAND = 'v'
    ARGS = ['x2', 'y2', 'x3', 'y3']

    def transform(self, t):
        x2, y2 = transform_point((self.x2, self.y2), t)
        x3, y3 = transform_point((self.x3, self.y3), t)
        return BezierV(x2, y2, x3, y3)


class BezierY(metaclass=FloatTupleCommand):
    """Cubic bezier curve, from the current point to (x3, y3), using (x1, y1)
    and (x3, y3) as control points.
    """
    COMMAND = 'y'
    ARGS = ['x1', 'y1', 'x3', 'y3']

    def transform(self, t):
        x1, y1 = transform_point((self.x1, self.y1), t)
        x3, y3 = transform_point((self.x3, self.y3), t)
        return BezierY(x1, y1, x3, y3)


class MatrixCommand(TupleCommand):
    def __new__(cls, name, parents, attrs):
        attrs['ARGS'] = ['matrix']
        attrs['NUM_ARGS'] = 6

        return super(MatrixCommand, cls).__new__(cls, name, parents, attrs)

    def __init__(cls, name, parents, attrs):
        def transform(self, t):
            return cls(matrix_multiply(t, self.matrix))

        def resolve(self):
            return ' '.join([format_number(n) for n in self.matrix] + [self.COMMAND])

        @classmethod
        def from_tokens(cls, idx, tokens):
            return cls([float(tok) for tok in cls._get_tokens(idx, tokens)])

        def __init__(self, matrix):
            if len(matrix) != 6:
                raise ValueError('go away you bad dude')

        setattr(cls, 'transform', transform)
        setattr(cls, 'resolve', resolve)
        setattr(cls, 'from_tokens', from_tokens)
        setattr(cls, '__init__', __init__)


class TextMatrix(metaclass=MatrixCommand):
    COMMAND = 'Tm'


class CTM(metaclass=MatrixCommand):
    COMMAND = 'cm'


def format_number(n):
    # Really small numbers should just be rounded to 0
    if -ZERO_TOLERANCE <= n <= ZERO_TOLERANCE:
        return '0'
    # Cut off unnecessary decimals
    if n % 1 == 0:
        return str(int(n))
    # Otherwise return 10 decimal places, but remove trailing zeros. I wish I
    # could use 'g' for this, but that switches to scientific notation at
    # certain thresholds.
    string = '{:.10f}'.format(n)
    i = len(string) - 1
    while string[i] == '0':
        i -= 1
    return string[:i + 1]


def quadratic_to_cubic_bezier(
    start_x, start_y,
    control_x, control_y,
    end_x, end_y
):
    """Make a cubic bezier curve from the parameters of a quadratic bezier.

    This is necessary because PDF doesn't have quadratic beziers.
    """
    cp1x = start_x + 2 / 3 * (control_x - start_x)
    cp1y = start_y + 2 / 3 * (control_y - start_y)
    cp2x = end_x + 2 / 3 * (control_x - end_x)
    cp2y = end_y + 2 / 3 * (control_y - end_y)
    return Bezier(cp1x, cp1y, cp2x, cp2y, end_x, end_y)
