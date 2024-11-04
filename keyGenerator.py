import sys
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def generate_key_pair(passphrase):
    try:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())
        ).decode()

        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        print(f"""Successfully created your public private key pair. Please copy the below values into your /.env file
************* COPY PASSPHRASE & PRIVATE KEY BELOW TO .env FILE *************
PASSPHRASE="{passphrase}"

PRIVATE_KEY="{private_key}"
************* COPY PASSPHRASE & PRIVATE KEY ABOVE TO .env FILE *************

************* COPY PUBLIC KEY BELOW *************
{public_key}
************* COPY PUBLIC KEY ABOVE *************
""")
    except Exception as e:
        print(f"Error while creating public private key pair: {e}")

if __name__ == "__app__":
    if len(sys.argv) != 2:
        print("Passphrase is empty. Please include passphrase argument to generate the keys.")
        sys.exit(1)

    passphrase = sys.argv[1]
    generate_key_pair(passphrase)