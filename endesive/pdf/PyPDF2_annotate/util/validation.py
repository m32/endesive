# -*- coding: utf-8 -*-
"""
    Validation Utils
    ~~~~~~~~~~~~~~~~

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import attr

NUMERIC_TYPES = (int, float)


def Boolean(**kwargs):
    _add_validator_to_kwargs(kwargs, instance_of(bool))
    return attr.ib(**kwargs)


def Integer(**kwargs):
    _add_validator_to_kwargs(kwargs, instance_of(int))
    return attr.ib(**kwargs)


def Number(**kwargs):
    _add_validator_to_kwargs(kwargs, is_number())
    return attr.ib(**kwargs)


def Enum(values, **kwargs):
    _add_validator_to_kwargs(kwargs, one_of(values))
    return attr.ib(**kwargs)


def String(**kwargs):
    _add_validator_to_kwargs(kwargs, instance_of(str))
    return attr.ib(**kwargs)


def List(**kwargs):
    _add_validator_to_kwargs(kwargs, instance_of(list))
    return attr.ib(**kwargs)


def Dict(**kwargs):
    _add_validator_to_kwargs(kwargs, instance_of(dict))
    return attr.ib(**kwargs)


def Color(**kwargs):
    """Color value. Can be specified as three-item list/tuple (RGB) or four-
    item list/tuple (RGBA).
    """
    _add_validator_to_kwargs(kwargs, is_color())
    return attr.ib(**kwargs)


def Points(**kwargs):
    _add_validator_to_kwargs(kwargs, is_points_list())
    return attr.ib(**kwargs)


def Field(allowed_type, **kwargs):
    """Generic field, e.g. Field(ContentStream)."""
    _add_validator_to_kwargs(kwargs, instance_of(allowed_type))
    return attr.ib(**kwargs)


def is_points_list():
    def validate(obj, attr, value):
        if isinstance(value, (list, tuple)):
            for point in value:
                if len(point) != 2 or not (
                    isinstance(point[0], NUMERIC_TYPES) and
                    isinstance(point[1], NUMERIC_TYPES)
                ):
                    raise ValueError(
                        'Value ({}) must be a list of points'.format(value)
                    )
        elif value is not None:
            raise ValueError(
                'Value ({}) must be a list of points'.format(value)
            )
    return validate


def greater_than_eq(i):
    def validate(obj, attr, value):
        if value is not None and not value >= i:
            raise ValueError('Value ({}) must be >= than {}'.format(value, i))
    return validate


positive = greater_than_eq(0)


def between(a, b):
    def validate(obj, attr, value):
        if value is not None and not (a <= value <= b):
            raise ValueError(
                'Value ({}) must be between {} and {}'.format(value, a, b)
            )
    return validate


def instance_of(types):
    def validate(obj, attr, value):
        if value is not None and not isinstance(value, _tupleize(types)):
            raise ValueError(
                'Value ({}) must be of type ({})'.format(value, types)
            )
    return validate


def is_number():
    def validate(obj, attr, value):
        if value is not None and not isinstance(value, NUMERIC_TYPES):
            raise ValueError('Value ({}) must be numeric'.format(value))
    return validate


def one_of(values):
    def validate(obj, attr, value):
        if value is not None and value not in values:
            raise ValueError(
                'Value ({}) must be in ({})'.format(value, values)
            )
    return validate


def is_color():
    def validate(obj, attr, value):
        if isinstance(value, (list, tuple)):
            if len(value) not in (3, 4):
                raise ValueError(
                    'Value ({}) is not a RGB(A) color'.format(value)
                )
            for component in value:
                if not (
                    isinstance(component, NUMERIC_TYPES) and
                    component >= 0 and
                    component <= 1
                ):
                    raise ValueError(
                        'Value ({}) is not a RGB(A) color'.format(value)
                    )
        elif value is not None:
            raise ValueError('Value ({}) is not a RGB(A) color'.format(value))
    return validate


def validate_dash_array(obj, attr, value):
    msg = (
        'Value ({}) must be a dash array of the form '
        '[dash_array, dash_phase], where dash_array is a list of integers,'
        ' and dash_phase is an integer'
    )
    if isinstance(value, list):
        if (
            len(value) != 2 or
            not isinstance(value[0], list) or
            any(not isinstance(x, int) for x in value[0]) or
            not isinstance(value[1], int)
        ):
            raise ValueError(msg.format(value))
    elif value is not None:
        raise ValueError(msg.format(value))


def _listify(v):
    if isinstance(v, tuple):
        return list(v)
    elif not isinstance(v, list):
        return [v]
    return v


def _tupleize(v):
    if isinstance(v, list):
        return tuple(v)
    elif not isinstance(v, tuple):
        return (v,)
    return v


def _add_validator_to_kwargs(kwargs, validator):
    existing = _listify(kwargs.pop('validator', []))
    existing.append(validator)
    kwargs['validator'] = existing
