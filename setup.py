#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='endesive',
    version=__import__('endesive').__version__,
    description='Library for digital signing and verification of digital signatures in mail, PDF and XML documents.',
    long_description=long_description,
    long_description_content_type='text/x-rst',
    url='https://github.com/m32/endesive',
    author='Grzegorz Makarewicz',
    author_email='mak@trisoft.com.pl',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Operating System :: OS Independent',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Communications :: Email',
        'Topic :: Security :: Cryptography',
        'Topic :: Office/Business',
        'Topic :: Text Processing',
        'Topic :: Multimedia :: Graphics',
    ],
    keywords='cryptography pki x509 smime email pdf pkcs11 asn1 xades',
    packages=find_packages(exclude=['examples', 'tests']),
    platforms=["all"],
    install_requires=['cryptography', 'asn1crypto', 'pyopenssl', 'pdfminer.six', 'lxml', 'pykcs11'],
)
