import argparse
import datetime
import hashlib
from keys import generate_key_pair, save_keys_to_file, load_keys_from_file
from signer import sign_message, save_signature_to_file, load_signature_from_file
from verifier import verify_signature


def main():
    parser = argparse.ArgumentParser(description='Digital Signature System')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Generate keys command
    gen_parser = subparsers.add_parser('generate', help='Generate key pair')
    gen_parser.add_argument('--key-size', type=int, default=2048, help='Key size in bits (default: 2048)')
    gen_parser.add_argument('--private-key', default='private_key.pem', help='Private key output file')
    gen_parser.add_argument('--public-key', default='public_key.pem', help='Public key output file')

    # Sign message command
    sign_parser = subparsers.add_parser('sign', help='Sign a message')
    sign_parser.add_argument('--message', help='Message to sign')
    sign_parser.add_argument('--message-file', help='File containing message to sign')
    sign_parser.add_argument('--private-key', default='private_key.pem', help='Private key file')
    sign_parser.add_argument('--signature', default='signature.bin', help='Signature output file')

    # Verify message command
    verify_parser = subparsers.add_parser('verify', help='Verify a signature')
    verify_parser.add_argument('--message', help='Message to verify')
    verify_parser.add_argument('--message-file', help='File containing message to verify')
    verify_parser.add_argument('--public-key', default='public_key.pem', help='Public key file')
    verify_parser.add_argument('--signature', default='signature.bin', help='Signature file')

    args = parser.parse_args()

    # Handle commands
    if args.command == 'generate':
        private_key, public_key = generate_key_pair(args.key_size)
        save_keys_to_file(private_key, public_key, args.private_key, args.public_key)

    elif args.command == 'sign':
        # Get message from file or command line
        if args.message_file:
            with open(args.message_file, 'rb') as f:
                message = f.read()
        elif args.message:
            message = args.message.encode('utf-8')
        else:
            parser.error("Either --message or --message-file is required")

        # Load private key and sign message
        private_key, _ = load_keys_from_file(args.private_key)
        signature = sign_message(message, private_key)
        save_signature_to_file(signature, args.signature)
        print(f"Message signed successfully")

    elif args.command == 'verify':
        # Get message from file or command line
        if args.message_file:
            with open(args.message_file, 'rb') as f:
                message = f.read()
        elif args.message:
            message = args.message.encode('utf-8')
        else:
            parser.error("Either --message or --message-file is required")

        # Load public key and verify signature
        _, public_key = load_keys_from_file(None, args.public_key)
        signature = load_signature_from_file(args.signature)

        if verify_signature(message, signature, public_key):
            # Create a verification certificate
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                message_preview = message.decode('utf-8')[:30] + "..." if len(message) > 30 else message.decode('utf-8')
            except UnicodeDecodeError:
                message_preview = "[Binary data]"
            message_hash = hashlib.sha256(message).hexdigest()

            print("\n===== VERIFICATION CERTIFICATE =====")
            print(f"Status: AUTHENTIC")
            print(f"Timestamp: {timestamp}")
            print(f"Message: \"{message_preview}\"")
            print(f"SHA-256: {message_hash}")
            print(f"Public Key: {args.public_key}")
            print(f"Signature File: {args.signature}")
            print("==================================\n")
            print("The digital signature confirms this message is authentic and has not been tampered with.")
        else:
            print("\n❌ VERIFICATION FAILED ❌")
            print("The signature does not match the message. It may have been tampered with or corrupted.")
            print("==================================\n")


if __name__ == "__main__":
    main()