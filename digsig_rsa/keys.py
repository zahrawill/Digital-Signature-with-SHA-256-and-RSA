from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_key_pair(key_size=2048):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Derive public key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


def save_keys_to_file(private_key, public_key, private_key_file="private_key.pem", public_key_file="public_key.pem"):
    with open(private_key_file, "wb") as f:
        f.write(private_key)

    with open(public_key_file, "wb") as f:
        f.write(public_key)

    print(f"Keys saved to {private_key_file} and {public_key_file}")


def load_keys_from_file(private_key_file="private_key.pem", public_key_file="public_key.pem"):
    private_key = None
    public_key = None

    if private_key_file:
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

    if public_key_file:
        with open(public_key_file, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read()
            )

    return private_key, public_key