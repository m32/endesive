import sys

import pdfbox
from jnius import JavaException, autoclass

pdfname = 'generated/pdf.pdf'
if len(sys.argv) > 1:
    pdfname = sys.argv[1]
# needs pdfbox-examples-3.0.5.jar; showSignature is private, main takes [password, file]
try:
    ShowSignature = autoclass('org.apache.pdfbox.examples.signature.ShowSignature')
    ShowSignature.main(['', pdfname])
except JavaException as e:
    # no examples jar, or e.g. the chain of a demo certificate without its root CA
    print("ShowSignature failed:", e.classname, e.innermessage)
# PDFBox 3: PreflightParser.validate replaces parse/getPreflightDocument/validate
File = autoclass('java.io.File')
PreflightParser = autoclass('org.apache.pdfbox.preflight.parser.PreflightParser')
result = PreflightParser.validate(File(pdfname))
if result.isValid():
    print("The file:{} is a valid PDF/A-1b file".format(pdfname))
else:
    print("The file: {} is not valid, error(s) :".format(pdfname))
    for error in result.getErrorsList():
        print(error.getErrorCode(), " : ", error.getDetails())
