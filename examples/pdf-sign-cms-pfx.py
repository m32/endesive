#!/usr/bin/env vpython3

""" A tool which takes in pdf, pfx file, password as input and gives out a corresponding signed pdf

"""
import argparse
import pytz
import re
import sys
import datetime

from OpenSSL.crypto import load_pkcs12
from endesive import pdf

signature_string = lambda organization, date, country : (organization + '\nDATE: '+ date)

def eprint(error):
    print(error, file=sys.stderr)

def load_pfx(file_path, password):
    """ Function to load pkcs12 object from the given password protected pfx file."""

    return load_pkcs12(open(file_path, 'rb').read(), password.encode())

def create_args():
    """Creates CLI arguments for the pdfSigner script."""

    parser = argparse.ArgumentParser(description='Script for digitally signing a pdf')
    parser.add_argument('pfx_certificate', type=str, help='Specify keystore file in .pfx format (Mandatory)')
    parser.add_argument('password', type=str, help=' Specify password for keystore file (mandatory)')
    parser.add_argument('src', type=str,
        help='Specify the source file (.pdf) that needs to be digitally signed. Only 1 file at a time can be signed. (Mandatory) ')
    parser.add_argument('-d', '--dest', type=str,
        help='Specify the destination file where digitally signed content will be stored.When not specified, by default it will '
        'digitally sign the source file.(Mandatory) \n'
        'E.g. Given source file /var/hp/some.pdf will be digitally signed')
    parser.add_argument('-c', '--coords', type=str,
        help='Specify the co-ordinates of where you want the digital signature to be placed on the PDF file page.(Optional)\n'
        'Format: Accepts 4 comma-separated float values (without spaces). E.g. 1,2,3,4 ')
    parser.add_argument('-p', '--page', type=int,
        help='You can specify the page number of PDF file where digital signature(Optional)')

    return parser.parse_args()

def validate_args(args):
    """Validating commandline arguments raises valueError exception with if any command
    line arguments are not valid."""

    IS_PFX = lambda pfx_certificate: re.match( r'^(.[^,]+)(.pfx|.PFX){1}$', pfx_certificate)
    if not IS_PFX(args.pfx_certificate):
        raise ValueError('Not a proper pfx file with .pfx or .PFX extension')
    if args.coords:
        for num in args.coords.split(','):
            if not num.isdigit():
                raise ValueError('Coords are not integers')

def run():
    args = create_args()

    try:
        validate_args(args)
    except ValueError as e:
        import traceback; traceback.print_exc()
        sys.exit(1)

    try:
        # Load the PKCS12 object from the pfx file
        p12 = load_pfx(args.pfx_certificate, args.password)

        subject = p12.get_certificate().get_subject()
        timezone = pytz.timezone('Asia/Calcutta')
        #default coords of bottom right corner in a pdf page
        coords = [350, 50, 550, 150]
        if args.coords:
          coords = [int(coord) for coord in args.coords.split(',') if coord]
        page = args.page if args.page else 1
        dest = args.dest if args.dest else args.src
        date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
        date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
        signature = signature_string(subject.CN, date, subject.C)
        dct = {
          b'sigflags': 3,
          b'sigpage': page - 1,
          b'contact': b'finacctind@endurance.com',
          #b'location': subject.C.encode(),
          b'location': b'Szczecin',
          b'signingdate': date.encode(),
          b'signingdate': b'20191122082642+02\'00\'',
          b'reason': b'Signed by endurance',
          b'signature': signature.encode(),
          b'signaturebox': tuple(coords[:4]),
        }

        input_file = args.src
        datau = open(input_file, 'rb').read()
        datas = pdf.cms.sign(datau,
                     dct,
                     p12.get_privatekey().to_cryptography_key(),
                     p12.get_certificate().to_cryptography(),
                     [],
                     'sha256'
                     )

        output_file = input_file.replace(input_file, dest)
        with open(output_file, 'wb') as fp:
          fp.write(datau)
          fp.write(datas)
    except Exception as e:
        import traceback; traceback.print_exc()
        eprint(e)
        sys.exit()

if __name__ == '__main__':
    run()
