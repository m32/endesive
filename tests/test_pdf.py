import datetime
import hashlib
import io
import unittest
import zlib
from types import SimpleNamespace
from unittest import mock

import PIL.Image
import pypdf
from cryptography import x509

from test_cert import (
    CA,
    ca_root_cert,
    cert1_p12,
    cert3_p12,
    fixture,
)

from endesive import pdf
from endesive.pdf.PyPDF2_annotate.annotations.image import Image as AnnotationImage
from endesive import exceptions


class PDFTests(unittest.TestCase):
    @staticmethod
    def _build_minimal_signed_pdf(signature_hex: bytes = b"30") -> bytes:
        # Build a minimal PDF-like byte stream containing a valid ByteRange marker.
        base = (
            b"%PDF-1.7\n"
            b"/ByteRange [0000000000 0000000000 0000000000 0000000000]\n<"
            + signature_hex
            + b">\n"
        )
        start = base.find(b"[")
        stop = base.find(b"]", start)
        open_angle = base.find(b"<", stop)
        close_angle = base.find(b">", open_angle)
        br = [0, open_angle, close_angle + 1, len(base) - (close_angle + 1)]
        bto = b"[%d %d %d %d]" % tuple(br)
        original = base[start : stop + 1]
        bto = bto + b" " * (len(original) - len(bto))
        return base[:start] + bto + base[stop + 1 :]

    def test_pdf(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_pss(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'pss': True,
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms-pss.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_aligned(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'aligned': 0,
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-cms-aligned.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_encrypted(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'aligned': 0,
            'password': '1234',
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf-encrypted.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_signature_appearance(self):
        dct = {
            'aligned': 0,
            'sigflags': 3,
            'sigflagsft': 132,
            'sigpage': 0,
            'sigbutton': False,
            'sigfield': 'Signature-1667820612.078739',
            'auto_sigfield': False,
            'sigandcertify': False,
            'signaturebox': [175.79446979865773, 294.7236779911374, 447.47683221476507, 573.2810782865583],
            'contact': '',
            'location': '',
            'reason': '',
            'signingdate': "D:20221107123012+00'00'",
            'signature_appearance': {
                'background': [0.75, 0.8, 0.95],
                'outline': [0.2, 0.3, 0.5],
                'border': 1,
                'labels': True,
                'display': ['date']
            }
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-appearance.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_signature_appearance_cn_of_certificate_without_cn(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        self.assertEqual(
            p12[1].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME), []
        )
        dct = {
            'sigflags': 3,
            'sigpage': 0,
            'auto_sigfield': True,
            'signaturebox': (72, 396, 360, 468),
            'signingdate': "D:20260101000000+00'00'",
            'signature_appearance': {'labels': True, 'display': ['CN', 'DN']},
        }
        with open(fixture('pdf.pdf'), 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct, p12[0], p12[1], p12[2], 'sha256')
        with open(ca_root_cert, 'rb') as fh:
            result, _ = pdf.verify(datau + datas, [fh.read()])
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_signature_appearance_ec(self):
        dct = {
            'aligned': 4096,
            'sigflags': 3,
            'sigflagsft': 132,
            'sigpage': 0,
            'sigbutton': False,
            'sigfield': 'Signature-1667820612.078739',
            'auto_sigfield': False,
            'sigandcertify': False,
            'signaturebox': [175.79446979865773, 294.7236779911374, 447.47683221476507, 573.2810782865583],
            'contact': '',
            'location': '',
            'reason': '',
            'signingdate': "D:20221107123012+00'00'",
            'signature_appearance': {
                'background': [0.75, 0.8, 0.95],
                'outline': [0.2, 0.3, 0.5],
                'border': 1,
                'labels': True,
                'display': ['date']
            }
        }
        p12 = CA().pk12_load(cert3_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-appearance-ec.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_sign_trailer_ids(self):
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('pdf.pdf'), 'rb') as fh:
            datau = fh.read()

        def trailer_id(udct):
            udct = {"signingdate": "D:20260101000000+00'00'", **udct}
            datas = pdf.cms.sign(datau, udct, p12[0], p12[1], p12[2], 'sha256')
            ids = pypdf.PdfReader(io.BytesIO(datau + datas)).trailer["/ID"]
            return [bytes(ids[0].original_bytes), bytes(ids[1].original_bytes)]

        first, second = trailer_id({}), trailer_id({})
        self.assertEqual([len(first[0]), len(first[1])], [16, 16])
        self.assertNotEqual(first[1], second[1])
        self.assertEqual(
            trailer_id({"id": b"0123456789abcdef", "newid": "revision"}),
            [b"0123456789abcdef", hashlib.md5(b"revision").digest()],
        )

    def test_pdf_image_raw_bytes_use_8_bits_per_component(self):
        pixels = {
            "L": [0, 17, 128, 255, 3, 99],
            "1": [0, 255, 255, 0, 0, 255],
            "RGB": [(255, 0, 0), (0, 255, 0), (0, 0, 255), (1, 2, 3), (4, 5, 6), (7, 8, 9)],
        }
        for mode, values in pixels.items():
            with self.subTest(mode):
                image = PIL.Image.new(mode, (3, 2))
                for i, value in enumerate(values):
                    image.putpixel((i % 3, i // 3), value)
                png = io.BytesIO()
                image.save(png, "PNG")
                image = PIL.Image.open(io.BytesIO(png.getvalue()))
                expected = bytes(
                    component
                    for value in values
                    for component in (value if isinstance(value, tuple) else (value,))
                )
                self.assertEqual(AnnotationImage.get_raw_image_bytes(image), expected)

    def test_pdf_signature_appearance_streams_are_compressed_once(self):
        # embedded fonts and images are zlib compressed before reaching
        # SignedData._extend, which must not compress them again
        png = io.BytesIO()
        PIL.Image.new("RGBA", (8, 4), (255, 0, 0, 128)).save(png, "PNG")
        dct = {
            "aligned": 0,
            "sigflags": 3,
            "sigpage": 0,
            "sigfield": "Signature1",
            "auto_sigfield": True,
            "signaturebox": (40, 110, 260, 190),
            "signature_manual": [
                ["image", "Logo", 0, 0, 40, 40],
                ["text_box", "zażółcić gęślą jaźń", "DejaVu", 50, 0, 170, 40, 10],
            ],
            "manual_images": {"Logo": PIL.Image.open(io.BytesIO(png.getvalue()))},
            "manual_fonts": {
                "DejaVu": "/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf",
            },
            "signingdate": "D:20260101000000+00'00'",
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        with open(fixture('pdf.pdf'), 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct, p12[0], p12[1], p12[2], 'sha256')

        reader = pypdf.PdfReader(io.BytesIO(datau + datas))
        objects = [
            reader.get_object(pypdf.generic.IndirectObject(idnum, generation, reader))
            for generation, ids in reader.xref.items()
            for idnum in ids
        ]
        flate_streams = [
            obj for obj in objects
            if isinstance(obj, pypdf.generic.StreamObject)
            and obj.get("/Filter") == "/FlateDecode"
        ]
        for obj in flate_streams:
            with self.assertRaises(zlib.error):
                zlib.decompress(obj.get_data())

        images = [obj for obj in flate_streams if obj.get("/Subtype") == "/Image"]
        self.assertEqual(len(images), 2)  # the image and its alpha mask
        for obj in images:
            channels = 1 if obj["/ColorSpace"] == "/DeviceGray" else 3
            self.assertEqual(len(obj.get_data()), obj["/Width"] * obj["/Height"] * channels)

        font_files = [
            obj["/FontFile2"].get_object().get_data()
            for obj in objects
            if isinstance(obj, pypdf.generic.DictionaryObject) and "/FontFile2" in obj
        ]
        self.assertTrue(font_files)
        for data in font_files:
            self.assertEqual(data[:4], b"\x00\x01\x00\x00")

    def test_pdf_signature_manual(self):
        date = datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=12)
        date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
        class User:
            full_name = 'u.full: ąćęłńóśżź'
            email = 'u.email: zażółcić gęślą jaźń'
            company = 'u.comp: ĄĆĘŁŃÓŚŻŹ'
            company_full_name = 'u.comp_full: ZAŻÓŁCIĆ GĘŚLĄ JAŹŃ'
        user = User()
        dct = {
            "aligned": 0,
            "sigflags": 3,
            "sigflagsft": 132,
            "sigpage": 0,
            "sigfield": "Signature1",
            "auto_sigfield": True,
            "signform": False,
            "signaturebox": (40, 110, 260, 190),
            "signature_manual": [
                ['text_box', f'Investor Name: {user.full_name}\nEmail: {user.email}\nDate: {date}\nLocation: Szczecin',
                    # font  *[bounding box], size, wrap, align, baseline, spacing
                    'default', 5, 10, 270, 40, 7, True, 'left', 'top'],
                ['fill_colour', 0.4, 0.4, 0.4],
                ['rect_fill', 0, 50, 250, 1],
                ['fill_colour', 0, 0, 0],
                ['text_box', user.company_full_name,
                    'DancingScript', 7, 25, 270, 50, 12, True, 'left', 'top', 1.2],
            ],
            "manual_fonts": {
            'DancingScript': '/usr/share/fonts/truetype/dejavu/DejaVuSansCondensed-Bold.ttf'
            },
            "contact": user.email,
            "location": "Szczecin",
            "signingdate": date,
            "reason": f"Investment in {user.company} by {user.company_full_name}",
        }

        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()
        datas = pdf.cms.sign(datau, dct,
            p12[0], p12[1], p12[2],
            'sha256'
        )
        fname = fname.replace('.pdf', '-signed-appearance-manual.pdf')
        with open(fname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = (fh.read(),)
        with open(fname, 'rb') as fh:
            data = fh.read()
        result, moredata = pdf.verify(
            data, trusted_cert_pems
        )
        assert result.signatureok and result.hashok and result.certok

    def test_pdf_timestamp_requires_tspurl(self):
        dct = {
            'sigflags': 3,
        }
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()

        with self.assertRaises(exceptions.TimestampError):
            pdf.cms.timestamp(datau, dct, 'sha256', None, None)

    def test_pdf_sign_autofills_ocsp_issuer_from_chain(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'ltv': True,
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()

        with mock.patch('endesive.pdf.cms.signer.fetch_ocsp_response', return_value=None) as ocsp_mock:
            pdf.cms.sign(
                datau,
                dct,
                p12[0],
                p12[1],
                p12[2],
                'sha256',
                ocspurl='https://ocsp.example',
                ocspoptions={},
            )

        self.assertTrue(ocsp_mock.called)
        self.assertTrue(
            any(
                isinstance(call.args[2], dict)
                and call.args[2].get('issuer') is not None
                for call in ocsp_mock.call_args_list
            )
        )

    def test_pdf_sign_continues_when_ocsp_is_unavailable(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'ltv': True,
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()

        with mock.patch('endesive.pdf.cms.signer.fetch_ocsp_response', return_value=None):
            datas = pdf.cms.sign(
                datau,
                dct,
                p12[0],
                p12[1],
                p12[2],
                'sha256',
                ocspurl='https://ocsp.example',
                ocspoptions={'issuer': p12[2][0]},
            )

        self.assertIsInstance(datas, bytes)
        self.assertGreater(len(datas), 0)

    def test_pdf_sign_fetches_ocsp_for_cms_even_when_ltv_disabled(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
            'ltv': False,
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()

        with mock.patch('endesive.pdf.cms.signer.fetch_ocsp_response', return_value=None) as ocsp_mock:
            datas = pdf.cms.sign(
                datau,
                dct,
                p12[0],
                p12[1],
                p12[2],
                'sha256',
                ocspurl='https://ocsp.example',
                ocspoptions={'issuer': p12[2][0]},
            )

        self.assertIsInstance(datas, bytes)
        self.assertTrue(ocsp_mock.called)

    def test_pdf_timestamp_raises_on_tsp_unavailable(self):
        dct = {
            'sigflags': 3,
        }
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()

        with mock.patch('endesive.pdf.cms.signer.fetch_tsp_response', return_value=None):
            with self.assertRaises(exceptions.TimestampError):
                pdf.cms.timestamp(
                    datau,
                    dct,
                    'sha256',
                    'https://tsa.example',
                    {'verify': False},
                )

    def test_pdf_verifier_maps_timestamp_only_payload(self):
        pdf_data = self._build_minimal_signed_pdf(b'30')

        verifier = pdf.PDFVerifier(pdf_data)
        fake_result = SimpleNamespace(
            signed_data={
                'encap_content_info': {
                    'content_type': SimpleNamespace(native='tst_info')
                }
            },
            crldata='crl',
            tsp_data=None,
        )

        with mock.patch.object(pdf.PDFVerifier, 'decompose_signed_data', return_value=fake_result):
            with mock.patch.object(pdf.PDFVerifier, 'verify_tsp_data', return_value=None) as tsp_mock:
                result, remaining = verifier.verify()

        self.assertIsNone(result.signed_data)
        self.assertEqual(result.tsp_data['encap_content_info']['content_type'].native, 'tst_info')
        self.assertIsNone(result.crldata)
        self.assertIsNone(remaining)
        tsp_mock.assert_called_once()

    def test_pdf_verifier_rejects_invalid_byterange_markers(self):
        pdf_data = self._build_minimal_signed_pdf(b'30').replace(b'<30>', b'(30)')

        with self.assertRaises(ValueError):
            pdf.PDFVerifier(pdf_data)

    def test_pdf_verifier_rejects_non_numeric_byterange(self):
        pdf_data = b"%PDF-1.7\n/ByteRange [a b c d]\n<30>\n"

        with self.assertRaises(ValueError):
            pdf.PDFVerifier(pdf_data)

    def test_pdf_verifier_verify_all_signatures_for_double_signed_pdf(self):
        dct = {
            'sigflags': 3,
            'contact': 'mak@trisoft.com.pl',
            'location': 'Szczecin',
            'signingdate': '20180731082642+02\'00\'',
            'reason': 'Dokument podpisany cyfrowo',
        }
        p12 = CA().pk12_load(cert1_p12, '1234')
        fname = fixture('pdf.pdf')
        with open(fname, 'rb') as fh:
            datau = fh.read()

        first_signed = datau + pdf.cms.sign(datau, dct, p12[0], p12[1], p12[2], 'sha256')
        second_signed = first_signed + pdf.cms.sign(first_signed, dct, p12[0], p12[1], p12[2], 'sha256')

        with open(ca_root_cert, 'rb') as fh:
            trusted_cert_pems = [fh.read()]

        verifier = pdf.PDFVerifier(second_signed, trusted_cert_pems)
        results = verifier.verify_all_signatures()

        self.assertGreaterEqual(len(results), 2)
        self.assertTrue(results[-1].signatureok)
        self.assertTrue(results[-1].hashok)

