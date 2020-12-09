# changelog

## 2.0.2
 - Text attributes for signature appearance

## 2.0.1
 - fix #74 accessing pages in big documents
 - Pass request options when performing the HTTP POST call against the timestamp server.

## 2.0.0
 - XADES signing time info (XADES-T) from TSP provider
 - XADES enveloping/enveloped format
 - Added example for Google HSM

## 1.5.12
 - Use sigflags within DocMDP for protecting PDFs.

## 1.5.11
 - Make /Info entry in trailer optional.

## 1.5.10
 - optional parameter timestampcredentials to sign

## 1.5.7
 - xref @1 was skipped when generating the uncompressed lookup table

## 1.5.6
 - forgotten font compression

## 1.5.5
 - stream compression improved, signatures in images work again

## 1.5.4
 - removed dependency on fonttools
 - added an internal class to support ttf

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
