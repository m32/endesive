# -*- coding: utf-8 -*-
"""
    Geometry
    ~~~~~~~~
    Geometry utility functions

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import math


def normalize_rotation(rotate):
    if rotate % 90:
        raise ValueError('Invalid Rotate value: {}'.format(rotate))
    while rotate < 0:
        rotate += 360
    while rotate >= 360:
        rotate -= 360
    return rotate


def to_radians(degrees):
    return degrees * math.pi / 180


def rotate(degrees):
    """Return a homogenous rotation matrix by degrees

    :params int degrees: integer degrees
    :returns list: matrix rotated by degrees, 6-item list
    """
    radians = to_radians(degrees)
    return [
        math.cos(radians),
        math.sin(radians),
        -math.sin(radians),
        math.cos(radians),
        0,
        0,
    ]


def translate(x, y):
    return [1, 0, 0, 1, x, y]


def scale(x_scale, y_scale):
    return [x_scale, 0, 0, y_scale, 0, 0]


def identity():
    return [1, 0, 0, 1, 0, 0]


def matrix_multiply(*args):
    """Multiply a series of matrices. len(args) must be at least two. If more
    than two matrices are specified, the multiplications are chained, with the
    left-most matrices being multiplied first.

    E.g. matrix_multiply(A, B, C) => (A*B)*C

    What this means for combining affine transformations is that they are
    applied in reverse order. For instance, to perform rotation R, scale S, and
    translation T, in that order, you would use:

    matrix_multiply(T, S, R)

    Each matrix is a 6-item homogenous matrix.
    """
    if len(args) < 2:
        raise ValueError('Cannot multiply fewer than two matrices')
    r = _matrix_multiply(args[0], args[1])
    for m in args[2:]:
        r = _matrix_multiply(r, m)
    return r


def matrix_inverse(matrix):
    """Invert a 6-item homogenous transform matrix.

    A transform matrix [a, b, c, d, e, f] is part of a 3x3 matrix:

        a b 0
        c d 0
        e f 1

    Invert it using the formula for the inverse of a 3x3 matrix from
    http://mathworld.wolfram.com/MatrixInverse.html
    """
    a, b, c, d, e, f = matrix

    determinant = float(a * d - b * c)
    unscaled = [d, -b, -c, a, c * f - d * e, b * e - a * f]

    return [x / determinant for x in unscaled]


def _matrix_multiply(A, B):
    a00, a01, a10, a11, a20, a21 = A

    b00, b01, b10, b11, b20, b21 = B
    b02, b12, b22 = 0, 0, 1

    # We don't have to compute all entries of the new matrix during
    # multiplication, since any multiple of affine transformations is an affine
    # transformation, and therefore homogenous coordinates.
    c00 = b00 * a00 + b01 * a10 + b02 * a20
    c01 = b00 * a01 + b01 * a11 + b02 * a21

    c10 = b10 * a00 + b11 * a10 + b12 * a20
    c11 = b10 * a01 + b11 * a11 + b12 * a21

    c20 = b20 * a00 + b21 * a10 + b22 * a20
    c21 = b20 * a01 + b21 * a11 + b22 * a21

    return [c00, c01, c10, c11, c20, c21]


def transform_point(point, matrix):
    """Transform point by matrix.

    :param list point: 2-item list
    :param list matrix: 6-item list representing transformation matrix
    :returns list: 2-item transformed point
    """
    x, y = point
    a, b, c, d, e, f = matrix
    # This leaves out some unnecessary stuff from the fact that the matrix is
    # homogenous coordinates.
    new_x = x * a + y * c + e
    new_y = x * b + y * d + f
    return [new_x, new_y]


def transform_vector(vector, matrix):
    """Transform a vector by a matrix. This is similar to transform_point,
    except that translation isn't honored. Think of a vector as displacement in
    space, and a point as, well, a point in space.

    :param list vector: 2-item list
    :param list matrix: 6-item list representing transformation matrix
    :returns list: 2-item transformed point
    """
    x, y = vector
    a, b, c, d, _, _ = matrix
    new_x = x * a + y * c
    new_y = x * b + y * d
    return [new_x, new_y]


def transform_rect(rect, matrix):
    """Transform a rectangle specified by two points (lower left and upper
    right) by a transformation matrix.

    :param list rect: [x1, y1, x2, y2]
    :param list matrix: transformation matrix
    :returns list: [x1, y1, x2, y2] with transformed points
    """
    x1, y1 = transform_point(rect[:2], matrix)
    x2, y2 = transform_point(rect[2:], matrix)

    x1, x2 = sorted([x1, x2])
    y1, y2 = sorted([y1, y2])

    return [x1, y1, x2, y2]
