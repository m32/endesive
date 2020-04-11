# -*- coding: utf-8 -*-
"""
    Font Metrics Utils
    ~~~~~~~~~~

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import attr

from .validation import Number, List, Dict


@attr.s
class FontMetrics:
    """
    Class to hold our font metric calculations.
    """
    italicAngle = Number(default=0)
    usWeightClass = Number(default=500)
    isFixedPitch = Number(default=0)

    unitsPerEm = Number(default=1000)
    scale = Number(default=float(1))
    bbox = List(default=[])

    ascent = Number(default=None)
    descent = Number(default=None)
    capHeight = Number(default=None)

    stemV = Number(default=None)
    defaultWidth = Number(default=None)
    widths = List(default=[])
    cmap = Dict(default={})

    @property
    def flags(self):
        """
        See Section 9.8.2 - Font Descriptor Flags of PDF 1.7 Spec
        Bit 1 - FixedPitch
        Bit 2 - Serif
        Bit 3 - Symbolic
        Bit 4 - Script
        Bit 6 - Nonsymbolic
        Bit 7 - Italic
        Bit 17 - AllCap
        Bit 18 - SmallCap
        Bit 19 - ForceBold
        :return:
        """
        flags = 4
        if self.italicAngle != 0:
            flags = flags | 64
        if self.usWeightClass >= 600:
            flags = flags | 262144
        if self.isFixedPitch:
            flags = flags | 1
        return flags
