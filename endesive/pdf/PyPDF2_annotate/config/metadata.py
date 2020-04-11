# -*- coding: utf-8 -*-
"""
    Metadata
    ~~~~~~~~
    Configuration for an annotation's metadata.

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
from datetime import datetime
from datetime import timedelta
from datetime import tzinfo
from uuid import uuid4


UNSET = object()


class UTC(tzinfo):
    def utcoffset(self, dt):
        return timedelta(0)

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return 'UTC'


class Flags(object):
    Invisible = 1
    Hidden = 2
    Print = 4
    NoZoom = 8
    NoRotate = 16
    NoView = 32
    ReadOnly = 64
    Locked = 128
    ToggleNoView = 256
    LockedContents = 512


class Metadata(object):
    """PDF annotation metadata class.

    By default, new annotations get the following properties:
        * CreationDate - defaults to UTC now
        * M (modified date) - defaults to UTC now
        * NM (unique name) - defaults to uuid4()
        * F (flags) - defaults to 4, just Flags.Print

    Datetime objects should be timezone-aware. If they're not, UTC is used.

    To leave any of these entries off the created annotation, pass kwarg=UNSET.

    Any additional kwargs will be set on the annotation object as /Name value.
    So for instance if you use Metadata(Subj='hi'), the annotation object in
    the PDF will have an attribute of `/Subj (hi)`. Acceptable value types are
    str, int, float, datetime, and lists of str/int/float. Other values may
    work, but may appear oddly formatted in the PDF, or break it entirely.
    """

    def __init__(
        self,
        creation_date=None,
        modified_date=None,
        name=None,
        flags=None,
        **kwargs
    ):
        """
        :param datetime|None|UNSET creation_date:
        :param datetime|None|UNSET modified_date:
        :param str|None|UNSET name:
        :param int|None|UNSET flags: if specified, a bunch of bitwise or-ed
            `Flags` values. For instance, to specify both Hidden and Invisible,
            use `Flags.Invisible | Flags.Hidden`. If flags are specified, the
            default `Print` flag is no longer set; it must be set explicity.
        """
        self.metadata = {}
        self.set('CreationDate', creation_date, self.now)
        self.set('M', modified_date, self.now)
        self.set('NM', name, lambda: str(uuid4()))
        self.set('F', flags, lambda: Flags.Print)

        for k, v in kwargs.items():
            if v is None:
                raise ValueError("Can't write Nones to PDF")
            self.set(k, v, None)

    def set(self, attr, value, default_func):
        if value is UNSET:
            return
        self.metadata[attr] = default_func() if value is None else value

    def iter(self):
        for name, value in self.metadata.items():
            yield name, value

    @staticmethod
    def now():
        return datetime.utcnow().replace(tzinfo=UTC())


def serialize_value(value):
    if isinstance(value, datetime):
        return serialize_datetime(value)
    return value


def serialize_datetime(d):
    if d.tzinfo is None:
        d = d.replace(tzinfo=UTC())
    offset_str = d.strftime('%z')
    offset_str = "{}'{}".format(offset_str[:3], offset_str[3:])
    return d.strftime('D:%Y%m%d%H%M%S{}'.format(offset_str))
