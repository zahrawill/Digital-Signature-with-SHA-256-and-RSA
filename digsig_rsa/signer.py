from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def sign_message(message, private_key):
    # Convert message to bytes if it's not already
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Create signature
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def save_signature_to_file(signature, filename="signature.bin"):
    with open(filename, "wb") as f:
        f.write(signature)

    print(f"Signature saved to {filename}")


def load_signature_from_file(filename="signature.bin"):
    with open(filename, "rb") as f:
        signature = f.read()

    return signature