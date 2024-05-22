from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

message = b'This is a secret message'
signature = sign_message(private_key, message)
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Load the keys from files (optional)
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Verify the signature
is_valid = verify_signature(public_key, message, signature)
print(f"Signature valid: {is_valid}")


private_numbers = private_key.private_numbers()

# Extract and print the components
print("Modulus (n):", private_numbers.public_numbers.n)
print("Public Exponent (e):", private_numbers.public_numbers.e)
print("Private Exponent (d):", private_numbers.d)
print("Prime 1 (p):", private_numbers.p)
print("Prime 2 (q):", private_numbers.q)
print("Exponent 1 (d mod (p-1)):", private_numbers.dmp1)
print("Exponent 2 (d mod (q-1)):", private_numbers.dmq1)
print("Coefficient ((inverse of q) mod p):", private_numbers.iqmp)
