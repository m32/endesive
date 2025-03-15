#!/bin/sh
#
# https://about.codecov.io/blog/python-code-coverage-using-github-actions-and-codecov/
#
#vpy3-pytest --cov=./endesive --cov-report=xml $*
rm -rf \
tests/fixtures/softhsm2 \
tests/fixtures/softhsm2.conf \
tests/fixtures/cert-* \
tests/fixtures/demo2_*
vpython3 -m coverage run \
--omit \
"endesive/pdf/PyPDF2/*",\
"endesive/pdf/PyPDF2_annotate/*",\
"endesive/pdf/fpdf/*",\
"endesive/pdf/pdf.py",\
"/usr/lib/*" \
-m unittest discover tests
vpy3-coverage3 report -m
