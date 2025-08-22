from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

signing_pub = "./VSSH_client/public_key.pem"
signing_pri = "./Verifier/private_key.pem"


def generate_signing_keys(public_path, private_path):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=None
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_path, 'wb') as f:
        f.write(pem_private)

    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_path, 'wb') as f:
        f.write(pem_public)

generate_signing_keys(signing_pub, signing_pri)
print(f"public signing key is stored in {signing_pub}\nprivate signing key is stored in {signing_pri}")


