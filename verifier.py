import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import Invalidsign

def verify_sign(file_path, N, e, sign_hex):
    sha256_bytes = get_hash(file_path)

    sign = bytes.fromhex(sign_hex)

    public_numbers = rsa.RSAPublicNumbers(e, N)
    public_key = public_numbers.public_key()

    try:
        public_key.verify(
            sign,
            sha256_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "accept"  
    except Invalidsign:
        return "reject" 

def get_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.digest()

 if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python3 verifier.py <file_path> <N> <e> <sign_hex>")
        sys.exit(1)

    file_path = sys.argv[1]
    N = int(sys.argv[2])
    e = int(sys.argv[3])
    sign_hex = sys.argv[4]

    try:
        result = verify_sign(file_path, N, e, sign_hex)
        print(f"Verification Result: {result}")
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")