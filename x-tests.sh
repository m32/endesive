#!/bin/sh
#
# https://about.codecov.io/blog/python-code-coverage-using-github-actions-and-codecov/
#
#vpy3-pytest --cov=./endesive --cov-report=xml $*
vpython3 -m coverage run --omit "endesive/pdf/PyPDF2/*","endesive/pdf/fpdf/*" -m unittest discover tests
vpy3-coverage3 report
