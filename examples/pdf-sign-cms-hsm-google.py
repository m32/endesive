import datetime
from endesive import hsm, pdf
from google.cloud import kms
import hashlib

#fill out these variables based on your project
project_id = ""
location_id = ""
key_ring_id = ""
key_id = ""
version_id = ""
filepath = ""

class GoogleHSM(hsm.BaseHSM):
    
    def __init__(self, project_id, location_id, key_ring_id, key_id, version_id):
        
        self.project_id = project_id
        self.location_id = location_id
        self.key_ring_id = key_ring_id
        self.key_id = key_id
        self.version_id = version_id

    def certificate(self):

        """
        See my gist to find out how to create x509 certificates for
        Google HSM-hosted keys: https://gist.github.com/Arbitrage0/de4e0defb20bc539d6db27e4334e0e67
        """

        cert = open('path/to/certificate.crt.pem', 'rb').read()
        return 1, cert

    def sign(self, keyid, data, mech):
       
        """ 
        Following the example here: 
        https://github.com/googleapis/python-kms/blob/master/samples/snippets/sign_asymmetric.py 
        """
        
        client = kms.KeyManagementServiceClient()
        key_version_name = client.crypto_key_version_path(
            self.project_id, 
            self.location_id, 
            self.key_ring_id, 
            self.key_id, 
            self.version_id
        )
        hash_ = getattr(hashlib, mech.lower())(data).digest()
        digest = {mech.lower(): hash_}
        sign_response = client.asymmetric_sign(request={'name': key_version_name, 'digest': digest})
        return sign_response.signature

def main(project_id, location_id, key_ring_id, key_id, version_id, fname):
    
    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('D:%Y%m%d%H%M%S+00\'00\'')
    dct = {
        'sigflags': 3,
        'contact': 'user@example.com',
        'location': 'England',
        'signingdate': date.encode(),
        'reason': 'Test',
    }
    Ghsm = GoogleHSM(project_id, location_id, key_ring_id, key_id, version_id)
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
        None, None,
        [],
        'sha256',
        Ghsm,
    )
    fname = fname.replace('.pdf', '-signed-cms-hsm-Google.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)

main(project_id, location_id, key_ring_id, key_id, version_id, filepath)
