# changelog

## 1.5.0

 - removed dependency on pdfminer.six - library does not allow saving password protected pdfs
 - added internal copy of pypdf2
 - an internal pdf-annotation port has been added to conveniently create annotations
 - new parameters for signing pdf documents:
    'sigflagsft' - annotation flags
    'password' - for password encypted documents
 - dictionary key names for pdf signing are now strings, not bytes
 - the values of the pdf signing dictionary that were bytes are now strings
 - the dictionary value for the 'signature' key must match latin1 encoding,
    other encodings are not supported
