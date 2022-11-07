# -*- coding: utf-8 -*-
"""
    Signature Annotations
    ~~~~~~~~~~~~~~~~~~~~~~~
    Annotations defined by a width and a height: Square, Circle

    :copyright: Copyright 2019 Autodesk, Inc.
    :license: MIT, see LICENSE for details.
"""
import os.path

from ..pdfrw import PdfArray, PdfName, IndirectPdfDict, PdfDict
from ..pdfttf import TTFFont

from .image import Image
from .text import get_text_commands
from .base import Annotation
from .base import make_border_dict
from ..util.geometry import transform_rect
from ..util.geometry import identity
from ..config.appearance import set_appearance_state
from ..config.appearance import stroke_or_fill
from ..config.constants import DEFAULT_BASE_FONT
from ..config.constants import GRAPHICS_STATE_NAME
from ..config.constants import PDF_ANNOTATOR_FONT
from ..graphics import BaseCommand, FloatTupleCommand
from ..graphics import Bezier
from ..graphics import Close
from ..graphics import ContentStream
from ..graphics import Line
from ..graphics import Move
from ..graphics import quadratic_to_cubic_bezier
from ..graphics import Rect
from ..graphics import Restore
from ..graphics import Save
from ..graphics import BeginText, Text, EndText, TextMatrix
from ..graphics import Font
from ..graphics import FillColor, StrokeColor, Stroke, StrokeWidth, Fill
from ..graphics import CTM, XObject

HELVETICA_PATH = os.path.join(os.path.dirname(__file__), "..", "fonts", "Helvetica.ttf")

class Signature(Annotation):
    """Signatur annotation that defines its location on the document with a
    width and a height.  Internal structure follows that which is documented
    by Adobe, with /frm referencing a blank /n0 layer with all the appearance
    in the stream of the /n2 layer.
    """

    subtype = 'Widget'

    def __init__(self, location, appearance, metadata=None):
        super(Signature, self).__init__(location, appearance, metadata)
        self._images = {}
        self._ttf = {}
        self._type1 = {}

    def simple_signature(self, signature):
        """
            simple_signature(self, signature)

            A simple signature annotation whose appearance is inspired by
            the signatures from Adobe's appearances.  The text is output
            using the default font, and no calls to add_image or add_font
            are needed to use this.

            signature = dict(
                background = Image with alpha / None,
                icon = Image with alpha / None,
                labels = bool,
                CN = str,
                DN = str,
                date = str,
                contact = str,
                reason = str,
                location = str,
                software = str,
                outline = [R, G, B],
                border = int,
                )
        """
        bbox = self._internal_location()
        processor = SignatureAppearance(bbox, self._appearance, self._ttf, self._images)
        height = bbox[3] - bbox[1]
        width = bbox[2] - bbox[0]
        t_left = 5
        t_right = bbox[2]
        border = signature.get('border', 0)

        if signature.get('labels', False):
            labels = dict(
                DN = 'DN: ',
                CN = 'Digitally signed by ',
                date = 'Date: ',
                contact = 'Contact: ',
                reason = 'Reason: ',
                location = 'Location: ',
                software = 'Signing software: ',
                )
        else:
            labels = {}

        block = []
        for i in ('CN', 'DN', 'date', 'reason', 'contact', 'location', 'software'):
            if i not in signature:
                continue
            block.append('{}{}'.format(labels.get(i, ''), signature[i]))

        cs = ContentStream([Save()])
        if 'background' in signature:
            if type(signature['background']) == list:
                cs.extend(processor.fill_colour(*signature['background']))
                cs.extend(processor.rect_fill(*bbox))
            else:
                if 'bg' not in self._images:
                    self.add_image(signature['background'], 'Bg')
                cs.extend(processor.image('Bg', *bbox))

        cs.extend(processor.fill_colour(*signature.get('outline', [0, 0, 0])))
        cs.extend(processor.stroke_colour(*signature.get('outline', [0, 0, 0])))
        if border:
            cs.extend(processor.border(border))
        if 'icon' in signature:
            if 'icon' not in self._images:
                self.add_image(signature['icon'], 'Icon')
            i_w = self._images['Icon']['/Width']
            i_h = self._images['Icon']['/Height']

            if block:
                factor = 2.0
            else:
                factor = 1.0

            if i_h <= height and i_w <= width/factor:
                # image smaller than alloted half of box
                # vertically centre icon and expand text region
                t_left += i_w + 5
                dist = (height - i_h)/2
                if block:
                    i_box = [bbox[0], bbox[1]+dist, i_w+bbox[0], bbox[3]-dist]
                else:
                    dist2 = (width - i_w)/2
                    i_box = [bbox[0]+dist2, bbox[1]+dist, bbox[2]-dist2, bbox[3]-dist]
            elif (i_w/i_h) > ((width/factor)/height):
                # too wide
                t_left += (width/factor) + 5
                scale = (width/factor)/i_w
                dist = (height - i_h*scale)/2
                i_box = [bbox[0], bbox[1]+dist, width/factor, bbox[3]-dist]
            else:
                # too tall
                scale = height/i_h
                t_left += (i_w*scale) + 5
                if block:
                    i_box = [bbox[0], bbox[1], bbox[0]+i_w*scale, bbox[3]]
                else:
                    # centre if only the icon
                    dist = (width - i_w*scale)/2
                    i_box = [bbox[0]+dist, bbox[1], bbox[2]-dist, bbox[3]]
            cs.extend(processor.image('Icon', *i_box))

        if block:
            font = self.get_default_font()
            cs.extend(processor.text_box('\n'.join(block), font, t_left, 5, (bbox[2]-5)-t_left, height-5))

        cs.add(Restore())
        self._n2_layer = cs

    def set_signature_appearance(self, *directives):
        """
            set_signature_apperance(self, *directives)

            Use the provided list of lists to compute a signature appearance
            using calls to the SignatureAppearance processor.  Note that the
            text_box directive can only be used with a TTF font.
        """
        processor = SignatureAppearance(self._internal_location(), self._appearance, self._ttf, self._images)
        cs = ContentStream([Save()])
        for x in directives:
            if x[0] in processor.template:
                directives = processor.template[x[0]](processor, *x[1:])
                if type(directives) != list:
                    directives = [directives]
                cs.extend(directives)
        cs.add(Restore())
        self._n2_layer = cs

    def make_rect(self):
        stroke_width = self._appearance.stroke_width
        L = self._location
        return [
            L.x1 - stroke_width,
            L.y1 - stroke_width,
            L.x2 + stroke_width,
            L.y2 + stroke_width,
        ]

    def add_default_font(self):
        self.add_ttf_font(HELVETICA_PATH, PDF_ANNOTATOR_FONT)

    def get_default_font(self):
        if PDF_ANNOTATOR_FONT not in self._ttf:
            self.add_ttf_font(HELVETICA_PATH, PDF_ANNOTATOR_FONT)
        return self._ttf[PDF_ANNOTATOR_FONT]

    def add_type1_font(self, base_font, name="Font", encoding='WinAnsiEncoding'):
        type1 = (
            'Helvetica', 'Helvetica-Bold', 'Helvetica-Oblique', 'Helvetica-BoldOblique',
            'Courier', 'Courier-Bold', 'Courier-Oblique', 'Courier-BoldOblique',
            'Times-Roman', 'Times-Bold', 'Times-Italic', 'Times-BoldItalic',
            'Symbol', 'ZapfDingbats',
            )
        if base_font in ('Symbol', 'ZapfDingbats'):
            encoding = base_font
        self._type1[name] = PdfDict(
            Type = PdfName('Font'),
            Subtype = PdfName('Type1'),
            Name = PdfName(name),
            BaseFont = PdfName(base_font),
            Encoding = PdfName(encoding),
            )

    def add_ttf_font(self, path, name="Font"):
        font = TTFFont(path)
        self._ttf[name] = font

    def add_image(self, obj, name="Image"):
        self._images[name] = Image.make_image_xobject(obj)

    def _make_appearance_stream_dict(self, bounding_box, transform):
        self._make_n0()
        self._make_n2()
        self._make_frm()
        self._make_apn()
        return PdfDict(N=self._apn)

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

    def _internal_location(self):
        L = self._location

        return (0, 0, L.x2 - L.x1, L.y2 - L.y1)

    def _make_apn(self):
        self._apn = IndirectPdfDict(
            BBox = self._internal_location(),
            Resources = dict(
                ProcSet = PdfArray([PdfName('PDF')]),
                XObject = {'FRM': self._frm},
            ),
            Type = PdfName('XObject'),
            Subtype = PdfName('Form'),
            FormType = 1,
            Matrix = identity(),
        )
        self._apn['stream'] = 'q 1 0 0 1 0 0 cm /FRM Do Q'

    def _make_frm(self):
        self._frm = IndirectPdfDict(
            BBox = self._internal_location(),
            Resources = dict(
                ProcSet = PdfArray([PdfName('PDF')]),
                XObject = {'n0': self._n0, 'n2': self._n2},
            ),
            Matrix = identity(),
            Type = PdfName('XObject'),
            Subtype = PdfName('Form'),
        )
        self._frm['stream'] = 'q 1 0 0 1 0 0 cm /n0 Do Q q 1 0 0 1 0 0 cm /n2 Do Q'

    def _make_n0(self):
        self._n0 = IndirectPdfDict(
            BBox = self._internal_location(),
            Type = PdfName('XObject'),
            Subtype = PdfName('Form'),
            FormType = 1,
            Matrix = identity(),
            Resources = {'ProcSet': PdfArray([PdfName('Text')])},
        )
        self._n0['stream'] = '% DSBlank'

    def _make_n2(self):
        resources = dict(
                ProcSet = PdfArray([PdfName('PDF'), PdfName('Text'), PdfName('ImageC')])
        )
        fonts = PdfDict()
        if self._ttf:
            for name, font in self._ttf.items():
                fonts[name] = font.get_font()
        if self._type1:
            for name, font in self._type1.items():
                fonts[name] = font
        if fonts:
            resources[PdfName('Font')] = fonts
        if self._images:
            resources[PdfName('XObject')] = self._images
        self._n2 = IndirectPdfDict(
            BBox = self._internal_location(),
            Matrix = identity(),
            Type = PdfName('XObject'),
            Subtype = PdfName('Form'),
            FormType = 1,
            Resources = resources,
            )
        self._n2['stream'] = self._n2_layer.resolve()

class SignatureAppearance():
    def __init__(self, box, appearance, ttf, images):
        self._in_text = False
        self._reset_font = True
        self._reset_tm = False
        self._cur_font = (PDF_ANNOTATOR_FONT, appearance.font_size)
        self._cur_tm = [1, 0, 0, 1, 0, 0]
        self._sc = [0, 0, 0]
        self._fc = [0, 0, 0]
        self._bounds = box
        self._ttf = ttf
        self._images = images

    def fill_colour(self, *colour):
        self._fc = colour
        return [FillColor(*colour)]

    def stroke_colour(self, *colour):
        self._sc = colour
        return [StrokeColor(*colour)]

    def border(self, inset):
        box = self._bounds
        return [
            Rect(inset, inset, box[2]-2*inset, box[3]-2*inset),
            Stroke()
            ]

    def image(self, image_name, x1, y1, x2, y2, distort=True, centred=True):
        if distort:
            scale_x = x2-x1
            scale_y = y2-y1
        else:
            max_w = x2-x1
            max_h = y2-y1
            i_w = self._images[image_name]['/Width']
            i_h = self._images[image_name]['/Height']

            if i_w/i_h >= max_w/max_h:
                # image proportionally wider than box
                scale_x = x2-x1
                scale_y = scale_x*(i_h/i_w)
                if centred: # centre vertically
                    dist = (max_h-scale_y)/2.0
                    y1 += dist
            elif i_w/i_h < max_w/max_h:
                # image proportionally narrower than box
                scale_y = y2-y1
                scale_x = scale_y*(i_w/i_h)
                if centred: # centre horizontally
                    dist = (max_w-scale_x)/2.0
                    x1 += dist

        commands = []
        if self._in_text:
            commands.append(EndText())
            self._reset_font = True
            self._reset_tm = True
            self._in_text = False
        commands.append(Save())
        commands.append(CTM((scale_x, 0, 0, scale_y, x1, y1)))
        commands.append(XObject(image_name))
        commands.append(Restore())
        return commands

    def rect(self, *box):
        seq = []
        if self._in_text:
            seq.append(EndText())
            self._in_text = False
        seq.extend([
            Rect(*box),
            Stroke()
            ])
        return seq

    def rect_fill(self, *box):
        seq = []
        if self._in_text:
            seq.append(EndText())
            self._in_text = False
        seq.extend([
            Rect(*box),
            Fill()
            ])
        return seq

    def reset(self):
        return [
            StrokeColor(0, 0, 0),
            FillColor(0, 0, 0),
            ]

    def text_position(self, x, y):
        if x < 0:
            x = self._bounds[2]+x
        if y < 0:
            y = self._bounds[3]+y

        self._cur_tm[4] = x
        self._cur_tm[5] = y
        if self._in_text:
            return [TextMatrix(self._cur_tm.copy())]
        self._reset_tm = True
        return []

    def font(self, name, size):
        if name == 'default':
            name = PDF_ANNOTATOR_FONT

        self._cur_font = (name, size)
        if self._in_text:
            return [Font(name, size), TextLeading(size*1.2)]
        self._reset_font = True
        return []

    def text_box(self, text, ttf_font, x, y, width, height, font_size=8, wrap_text=True, align='left', baseline='middle', line_spacing=1.2):
        if type(ttf_font) == str:
            font = self._ttf.get(ttf_font, None)
            if font is None:
                font = self._ttf[PDF_ANNOTATOR_FONT]
                fontname = PDF_ANNOTATOR_FONT
            else:
                fontname = ttf_font
        else:
            font = ttf_font
            fontname = font.font["name"]
        font.set_size(font_size)
        font.set_text(text)

        commands = []
        if not self._in_text:
            commands.extend([BeginText(), Font(fontname, font_size)])
        commands.extend(get_text_commands(x, y, x+width, y+height, text, font_size, wrap_text, align, baseline, line_spacing, font))
        if not self._in_text:
            commands.append(EndText())
        return commands

    def text(self, text):
        if self._cur_font[0] in self._ttf:
            ttf_font = self._ttf[self._cur_font[0]]
            ttf_font.set_size(self._cur_font[1])
            ttf_font.set_text(text)
            text = text.encode("utf-16be").decode("latin1")
        commands = []
        if not self._in_text:
            commands.append(BeginText())
            self._in_text = True
        if self._reset_tm:
            commands.append(TextMatrix(self._cur_tm.copy()))
            self._reset_tm = False
        if self._reset_font:
            commands.append(Font(*self._cur_font))
            commands.append(TextLeading(self._cur_font[1]*1.2))
            self._reset_font = False
        commands.append(Text(text))
        return commands

    def new_line(self):
        if self._in_text:
            return [ NewLine() ]
        return []

    def done(self):
        if self._in_text:
            self._in_text = False
            return [ EndText() ]
        return []

    template = dict(
        save = Save,
        reset = reset,
        image = image,
        rect = rect,
        rect_fill = rect_fill,
        border = border,
        font = font,
        text = text,
        text_box = text_box,
        text_position = text_position,
        new_line = new_line,
        done = done,
        fill_colour = fill_colour,
        stroke_colour = stroke_colour,
        fill_color = fill_colour,
        stroke_color = stroke_colour,
    )

class TextPosition(metaclass=FloatTupleCommand):
    COMMAND = 'Td'
    ARGS = ['x', 'y']

class TextRender(metaclass=FloatTupleCommand):
    COMMAND = 'Tr'
    ARGS = ['render']

class TextScale(metaclass=FloatTupleCommand):
    COMMAND = 'Tz'
    ARGS = ['scale']

class TextLeading(metaclass=FloatTupleCommand):
    COMMAND = 'TL'
    ARGS = ['leading']

class TextRise(metaclass=FloatTupleCommand):
    COMMAND = 'Ts'
    ARGS = ['rise']

class WordSpacing(metaclass=FloatTupleCommand):
    COMMAND = 'Tw'
    ARGS = ['wordSpace']

class CharacterSpacing(metaclass=FloatTupleCommand):
    COMMAND = 'Tc'
    ARGS = ['charSpace']

class StrokeGray(metaclass=FloatTupleCommand):
    COMMAND = 'G'
    ARGS = ['gray']

class FillGray(metaclass=FloatTupleCommand):
    COMMAND = 'g'
    ARGS = ['gray']

class NewLine(BaseCommand):
    COMMAND = 'T*'
