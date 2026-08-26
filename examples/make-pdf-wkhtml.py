from io import StringIO

from mako.runtime import Context
from mako.template import Template

raw_html = '<h1>Hello, ${name}!</h1>'
data = {'name': 'Tapan'}
pdf_name = 'generated/pdf-wkhtml.pdf'

mytemplate = Template(raw_html)
buf = StringIO()
ctx = Context(buf, **data)
mytemplate.render_context(ctx)
html = buf.getvalue()

import pdfkit

WKHTMLTOPDF_OPTIONS = {
    'page-size': 'A4',
    'encoding': 'UTF-8',
}

pdfkit.from_string(
    html,
    pdf_name,
    options=WKHTMLTOPDF_OPTIONS
)
