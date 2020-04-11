# -*- coding: utf-8 -*-
"""
    PdfAnnotator
    ~~~~~~~~~~~~
    The core annotator class.

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import warnings

#from pdfrw import PdfReader
#from pdfrw import PdfWriter

from .annotations.image import Image
from .annotations.points import Ink
from .annotations.points import Line
from .annotations.points import Polygon
from .annotations.points import Polyline
from .annotations.rect import Circle
from .annotations.rect import Square
from .annotations.text import FreeText
from .config.metadata import Metadata
from .config.metadata import UNSET
from .graphics import ContentStream
from .util.geometry import identity
from .util.geometry import matrix_multiply
from .util.geometry import normalize_rotation
from .util.geometry import rotate
from .util.geometry import scale
from .util.geometry import translate
from .util.validation import NUMERIC_TYPES


NAME_TO_ANNOTATION = {
    'square': Square,
    'circle': Circle,
    'line': Line,
    'polygon': Polygon,
    'polyline': Polyline,
    'ink': Ink,
    'text': FreeText,
    'image': Image,
}


class PDF(object):

    def __init__(self, pdf_reader):
        self._reader = pdf_reader
        self.pdf_version = self._reader.private.pdfdict.version

    def get_page(self, page_number):
        if page_number > len(self._reader.pages) - 1:
            raise ValueError('Page number {} out of bounds ({} pages)'.format(
                page_number,
                len(self._reader.pages),
            ))
        return self._reader.pages[page_number]

    def get_rotation(self, page_number):
        """Returns the rotation of a specified page."""
        page = self.get_page(page_number)
        rotate = int(page.inheritable.Rotate or 0)
        return normalize_rotation(rotate)


class PdfAnnotator(object):

    def __init__(self, file_or_reader, scale=None, compress=True):
        """Draw annotations directly on PDFs. Annotations are always drawn on
        as if you're drawing them in a viewer, i.e. they take into account page
        rotation and weird, translated coordinate spaces.

        :param str|PdfReader file_or_reader: filename of PDF or pdfrw.PdfReader
        :param number|tuple|None scale: number by which to scale coordinates
            to get to default user space. Use this if, for example, your points
            in the coordinate space of the PDF viewed at a dpi. In this case,
            scale would be 72/dpi. Can also specify a 2-tuple of x and y scale.
        :param bool compress: whether to output flate-compressed PDFs
        """
        if isinstance(file_or_reader, str):
            file_or_reader = PdfReader(file_or_reader)
        self._pdf = PDF(file_or_reader)
        self._scale = self._expand_scale(scale)
        self._dimensions = {}
        self._compress = compress

    def _expand_scale(self, scale):
        if scale is None:
            return 1, 1
        elif isinstance(scale, NUMERIC_TYPES):
            return (scale, scale)
        return scale

    def set_page_dimensions(self, dimensions, page_number):
        """Set dimensions for a given page number. If set, the dimensions for
        this page override the document-wide rotation and scale settings.

        :param tuple|None dimensions: As a convenient alternative to scale and
            you can pass in the dimensions of your sheet when viewed in a
            certain setting. For example, an 8.5"x11" PDF, rotated at 90° and
            rastered at 150 dpi, would produce dimensions of (1650, 1275). If
            you pass this in, you can then specify your coordinates in this
            coordinate space.
        :param int page_number:
        """
        self._dimensions[page_number] = dimensions

    def get_page_bounding_box(self, page_number):
        page = self._pdf.get_page(page_number)
        # PDF bounding boxes are complicated. We choose to use the CropBox, if
        # it's available, because that's what Acrobat uses to display the
        # actual PDF, and what pdfinfo uses to determine the PDF's dimensions.
        # If CropBox isn't available, we use MediaBox. We ignore the TrimBox
        # because Acrobat also ignores this when displaying the PDF.
        crop_box = page.inheritable.CropBox
        if crop_box is not None:
            return [float(n) for n in crop_box]
        return [float(n) for n in page.inheritable.MediaBox]

    def get_size(self, page_number):
        """Returns the size of the specified page's bounding box (pts),
        accounting for page rotation.

        :param int page_number:
        :returns tuple: If page is rotated 90° or 270°, the returned value will
            be (height, width) in PDF user space. Otherwise the returned value
            will be (width, height).
        """
        x1, y1, x2, y2 = self.get_page_bounding_box(page_number)
        rotation = self._pdf.get_rotation(page_number)

        if rotation in (0, 180):
            return (x2 - x1, y2 - y1)

        return (y2 - y1, x2 - x1)

    def add_annotation(
        self,
        annotation_type,
        location,
        appearance,
        metadata=None,
    ):
        """Add an annotation of the given type, with the given parameters, to
        the given location of the PDF.

        :param str annotation_type: E.g. 'square'
        :param Location location: Annotation's Location object, specified in
            the coordinate system of the client. Coordinates will be
            transformed to PDF user space via get_transform.
        :param Appearance appearance:
        :param Metadata|None|UNSET metadata: Metadata object. If UNSET, no
            metadata is written on the entire annotation. If None, default
            metadata is used.
        """
        self._before_add(location)
        metadata = self._resolve_metadata(metadata)
        self._validate_appearance_stream(appearance)
        annotation = self.get_annotation(
            annotation_type,
            location,
            appearance,
            metadata,
        )
        self._add_annotation(annotation)

    @staticmethod
    def _resolve_metadata(metadata):
        if isinstance(metadata, Metadata):
            return metadata
        elif metadata is None:
            return Metadata()
        elif metadata is UNSET:
            return None
        else:
            raise ValueError('Invalid metadata')

    @staticmethod
    def _validate_appearance_stream(appearance):
        stream = appearance.appearance_stream
        if stream is not None and not isinstance(stream, ContentStream):
            raise ValueError(
                'Invalid appearance stream format: {}'.format(type(stream)))

    def _before_add(self, location):
        # Steps to take before trying to add an annotation to `location`
        page = self._pdf.get_page(location.page)
        user_unit = page.inheritable.UserUnit
        if user_unit not in (1, None):
            warnings.warn(
                'Unsupported UserUnit (value: {})'.format(user_unit)
            )

    def get_annotation(self, annotation_type, location, appearance, metadata):
        # TODO filter on valid PDF versions, by type
        annotation_cls = NAME_TO_ANNOTATION.get(annotation_type)
        if annotation_cls is None:
            raise ValueError('Invalid/unsupported annotation type: {}'.format(
                annotation_type
            ))

        annotation = annotation_cls(location, appearance, metadata)
        annotation.validate(self._pdf.pdf_version)
        return annotation

    def get_scale(self, page_number):
        """Public API to get the x and y scales of the given page.

        :param int page_number:
        :returns 2-tuple: (x_scale, y_scale)
        """
        rotation = self._pdf.get_rotation(page_number)
        bounding_box = self.get_page_bounding_box(page_number)
        return self._get_scale(page_number, bounding_box, rotation)

    def get_rotation(self, page_number):
        """Public API to get the rotation of the give page.

        :param int page_number:
        :returns int: integer where i % 90 == 0
        """
        return self._pdf.get_rotation(page_number)

    def _get_scale(self, page_number, bounding_box, rotation):
        W = bounding_box[2] - bounding_box[0]
        H = bounding_box[3] - bounding_box[1]

        dimensions = self._dimensions.get(page_number)
        if dimensions is not None:
            # User-specified dimensions for a particular page just give us the
            # scaling factor to use for that page.
            width_d, height_d = dimensions
            width_pts, height_pts = W, H
            if rotation in (90, 270):
                width_pts, height_pts = H, W
            x_scale = (width_pts / float(width_d))
            y_scale = (height_pts / float(height_d))
        else:
            x_scale, y_scale = self._scale

        return x_scale, y_scale

    def get_transform(self, page_number, rotation):
        bounding_box = self.get_page_bounding_box(page_number)
        _scale = self._get_scale(page_number, bounding_box, rotation)
        return self._get_transform(bounding_box, rotation, _scale)

    @staticmethod
    def _get_transform(bounding_box, rotation, _scale):
        """Get the transformation required to go from the user's desired
        coordinate space to PDF user space, taking into account rotation,
        scaling, translation (for things like weird media boxes).
        """
        # Unrotated width and height, in pts
        W = bounding_box[2] - bounding_box[0]
        H = bounding_box[3] - bounding_box[1]

        scale_matrix = scale(*_scale)

        x_translate = 0 + bounding_box[0]
        y_translate = 0 + bounding_box[1]
        mb_translate = translate(x_translate, y_translate)

        # Because of how rotation works the point isn't rotated around an axis,
        # but the axis itself shifts. So we have to represent the rotation as
        # rotation + translation.
        rotation_matrix = rotate(rotation)

        translate_matrix = identity()
        if rotation == 90:
            translate_matrix = translate(W, 0)
        elif rotation == 180:
            translate_matrix = translate(W, H)
        elif rotation == 270:
            translate_matrix = translate(0, H)

        # Order matters here - the transformation matrices are applied in
        # reverse order. So first we scale to get the points in PDF user space,
        # since all other operations are in that space. Then we rotate and
        # scale to capture page rotation, then finally we translate to account
        # for offset media boxes.
        transform = matrix_multiply(
            mb_translate,
            translate_matrix,
            rotation_matrix,
            scale_matrix,
        )
        return transform

    def _add_annotation(self, annotation):
        """Add the annotation to the PDF document, transforming annotation
        metadata and content stream to PDF user space.
        """
        page = self._pdf.get_page(annotation.page)
        transform = self.get_transform(
            annotation.page,
            self._pdf.get_rotation(annotation.page),
        )
        annotation_obj = annotation.as_pdf_object(transform, page)

        if page.Annots:
            page.Annots.append(annotation_obj)
        else:
            page.Annots = [annotation_obj]

    def write(self, filename=None, overwrite=False):
        if filename is None and not overwrite:
            raise ValueError(
                'Must specify either output filename or overwrite flag'
            )
        if overwrite:
            filename = self._filename

        writer = PdfWriter(
            version=self._pdf.pdf_version,
            compress=self._compress,
        )
        writer.write(fname=filename, trailer=self._pdf._reader)
