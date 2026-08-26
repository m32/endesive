import sys

from jnius import autoclass

import pdfbox

pdfname = 'generated/pdf.pdf'
if len(sys.argv) > 1:
    pdfname = sys.argv[1]
signature = autoclass('org.apache.pdfbox.examples.examples.ShowSignature')
signature.showSignature('', pdfname)
parser.parse()
#org.apache.pdfbox.preflight.PreflightDocument
document = parser.getPreflightDocument()
document.validate()
result = document.getResult()
document.close()
if result.isValid():
    print("The file:{} is a valid PDF/A-1b file".format(pdfname))
else:
    print("The file: {} is not valid, error(s) :".format(pdfname))
    for error in result.getErrorsList():
        print(error.getErrorCode(), " : ", error.getDetails())
