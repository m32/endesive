'''
RSA-SHA-256: RSA signature condition using SHA-256.

This RSA condition uses RSA-PSS padding with SHA-256.
The salt length is set equal the digest length of 32 bytes.

The public exponent is fixed at 65537 and the public
modulus must be between 128 (1017 bits) and
512 bytes (4096 bits) long.

RSA-SHA-256 is assigned the type ID 3. It relies on
the SHA-256 and RSA-PSS feature suites which corresponds
to a feature bitmask of 0x11.

            parameters = sigalgo["parameters"]
            salgo = parameters["hash_algorithm"].native["algorithm"].upper()
            mgf = getattr(
                padding, parameters["mask_gen_algorithm"].native["algorithm"].upper()
            )(getattr(hashes, salgo)())
            salt_length = parameters["salt_length"].native
            try:
                public_key.verify(
                    signature,
                    signedData,
                    padding.PSS(mgf, salt_length),
                    getattr(hashes, salgo)(),
                )
                signatureok = True
            except:
                signatureok = False
'''
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def encrypt(message, public_key):
    # Hash the message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    hash_digest = digest.finalize()

    # Encrypt the hash with the public key
    encrypted = public_key.encrypt(
        hash_digest,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt(encrypted, private_key):
    # Decrypt the encrypted hash
    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def main():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Data to encrypt
    message = b"Hello, world!"

    if 0:
        encrypted = encrypt(message, public_key)
        decrypted = decrypt(encrypted, private_key)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        hash_digest = digest.finalize()
        print('ok?', hash_digest == decrypted)


    salt_length = 32 # length(hash_digest)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=salt_length,
        ),
        algorithm=hashes.SHA256(),
    )
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=salt_length
            ),
            algorithm=hashes.SHA256(),
        )
        ok = True
    except:
        ok = False
    print('ok=', ok)

main()
