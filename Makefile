test:
	rm -rf tests/fixtures/softhsm2 tests/fixtures/softhsm2.conf tests/fixtures/cert-* tests/fixtures/demo2_*
	vpython3 -m coverage run --omit "endesive/pdf/PyPDF2/*","endesive/pdf/PyPDF2_annotate/*","endesive/pdf/fpdf/*","endesive/pdf/pdf.py","/usr/lib/*" -m unittest discover tests
	vpy3-coverage3 report -m

mypy:
	mypy endesive --ignore-missing-imports --check-untyped --strict

docs:
	sphinx-apidoc -o docs ./endesive

.PHONY: test mypy docs
