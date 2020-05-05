# -*- coding: utf-8 -*-
"""
    Annotation
    ~~~~~~~~~~~~
    Base annotation class.

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
from ..pdfrw import PdfDict, PdfArray, PdfName, IndirectPdfDict

from ..config.constants import GRAPHICS_STATE_NAME
from ..config.metadata import serialize_value
from ..util.geometry import transform_rect
from ..util.geometry import translate


ALL_VERSIONS = ("1.3", "1.4", "1.5", "1.6", "1.7")


class Annotation(object):
    """Base class for all PDF annotation objects.

    Concrete annotations should define the following:
        * subtype (e.g. "Square")
        * make_rect() - bounding box of annotation
        * add_additional_pdf_object_data [optional] - additional entries to go
          in the PDF object
        * add_additional_resources [optional] - additional entries to go in the
          Resources sub-dict of the annotation

    There is a lot of nuance and viewer-specific (mostly Acrobat and Bluebeam)
    details to consider when creating PDF annotations. One big thing that's not
    immediately clear from the PDF spec is that wherever possible, we fill in
    the annotations' type-specific details (e.g. BE and IC for squares), but
    also create and include an Appearance Stream. The latter gives us control
    over exactly how the annotation appears across different viewers, while the
    former allows Acrobat or BB to regenerate the appearance stream during
    editing.
    """

    versions = ALL_VERSIONS

    def __init__(self, location, appearance, metadata=None):
        """
        :param Location location:
        :param Appearance appearance:
        :param Metadata metadata:
        """
        self._location = location
        self._appearance = appearance
        self._metadata = metadata

    def as_pdf_object(self, transform, page):
        """Return the PdfDict object representing the annotation, that will be
        inserted as is into the PDF document.

        :param list transform: Transformation matrix to transform the coords
            of the annotation from client-specified space to PDF user space.
        :param PdfDict page: The pdfrw page object from the PDF document
        :returns PdfDict: the annotation object to be inserted into the PDF
        """
        bounding_box = transform_rect(self.make_rect(), transform)
        appearance_stream = self._make_appearance_stream_dict(bounding_box, transform)

        obj = PdfDict(
            Type=PdfName("Annot"),
            Subtype=PdfName(self.subtype),
            Rect=bounding_box,
            AP=appearance_stream,
            P=page,
        )

        self._add_metadata(obj, self._metadata)
        self.add_additional_pdf_object_data(obj)
        obj.indirect = True

        return obj

    @property
    def page(self):
        return self._location.page

    def validate(self, pdf_version):
        """Validate a new annotation against a given PDF version."""
        pass

    def _add_metadata(self, obj, metadata):
        if metadata is None:
            return
        for name, value in metadata.iter():
            obj[PdfName(name)] = serialize_value(value)

    def _make_ap_resources(self):
        """Make the Resources entry for the appearance stream dictionary.

        Implement add_additional_resources to add additional entries -
        fonts, XObjects, graphics state - to the Resources dictionary.
        """
        resources = IndirectPdfDict(ProcSet=PdfArray([PdfName("PDF")]))
        self._add_graphics_state_resources(resources, self._appearance)
        self._add_xobject_resources(resources, self._appearance)
        self._add_font_resources(resources, self._appearance)
        self.add_additional_resources(resources)
        return resources

    @staticmethod
    def _add_font_resources(resources, A):
        if A.fonts:
            resources.Font = IndirectPdfDict()
            for font_name, font in A.fonts.items():
                resources.Font[PdfName(font_name)] = font

    @staticmethod
    def _add_xobject_resources(resources, A):
        """Adds in provided, explicit XObjects into the appearance stream's
        Resources dict. This is used when the user is explicitly specifying the
        appearance stream and they want to include, say, an image.
        """
        if A.xobjects:
            resources.XObject = IndirectPdfDict()
            for xobject_name, xobject in A.xobjects.items():
                resources.XObject[PdfName(xobject_name)] = xobject

    @staticmethod
    def _add_graphics_state_resources(resources, A):
        """Add in the resources dict for turning on transparency in the
        graphics state. For example, if both stroke and fill were transparent,
        this would add:
            << /ExtGState /PdfAnnotatorGS <<
                /CA 0.5 /ca 0.75 /Type /ExtGState
            >> >>
        to the Resources dict.

        Graphics states can also be specified externally, for use in explicit
        content streams. This is done by using the `graphics_states` property
        on the appearance object.
        """
        states = []
        internal_state = Annotation._get_internal_graphics_state(resources, A)
        if internal_state is not None:
            states.append((GRAPHICS_STATE_NAME, internal_state))

        if A.graphics_states:
            for name, state in A.graphics_states.items():
                states.append((name, state.as_pdf_dict()))

        if states:
            resources.ExtGState = PdfDict()
            for name, state in states:
                resources.ExtGState[PdfName(name)] = state

    @staticmethod
    def _get_internal_graphics_state(resources, A):
        internal_state = A.get_graphics_state()
        if internal_state.has_content():
            return internal_state.as_pdf_dict()

        return None

    def _make_appearance_stream_dict(self, bounding_box, transform):

        # Either use user-specified content stream or generate content stream
        # based on annotation type.
        stream = self._appearance.appearance_stream
        if stream is None:
            stream = self.make_appearance_stream()

        resources = self._make_ap_resources()

        # Transform the appearance stream into PDF space and turn it into a str
        appearance_stream = stream.transform(transform).resolve()

        normal_appearance = IndirectPdfDict(
            stream=appearance_stream,
            BBox=bounding_box,
            Resources=resources,
            Matrix=translate(-bounding_box[0], -bounding_box[1]),
            Type=PdfName("XObject"),
            Subtype=PdfName("Form"),
            FormType=1,
        )
        return PdfDict(N=normal_appearance)

    def add_additional_pdf_object_data(self, obj):
        """Add additional keys to the PDF object. Default is a no-op.

        :param PdfDict obj: the PDF object to be inserted into the PDF
        """
        pass

    def add_additional_resources(self, resources):
        """Add additional keys to the Resources PDF dictionary. Default is a
        no-op.

        :param PdfDict resources: Resources PDF dictionary
        """
        pass

    def make_rect(self):
        """Return a bounding box that encompasses the entire annotation."""
        raise NotImplementedError()


def make_border_dict(appearance):
    A = appearance
    return _make_border_dict(A.stroke_width, A.border_style, A.dash_array)


def _make_border_dict(width, style, dash_array=None):
    border = PdfDict(Type=PdfName("Border"), W=width, S=PdfName(style))
    if dash_array:
        if style != "D":
            raise ValueError("Dash array only applies to dashed borders!")
        border.D = dash_array
    return border


class Stamp(object):
    subtype = "Stamp"
