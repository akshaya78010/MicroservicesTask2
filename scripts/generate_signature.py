from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import subprocess

# 1. Get latest commit hash
commit_hash = subprocess.check_output(["git", "log", "-1", "--format=%H"]).decode().strip()
print("Commit Hash:", commit_hash)

# 2. Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 3. Sign commit hash using RSA-PSS-SHA256
signature = private_key.sign(
    commit_hash.encode("utf-8"),
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ),
    hashes.SHA256(),
)

# 4. Load instructor public key
with open("instructor_public.pem", "rb") as f:
    instructor_pub = serialization.load_pem_public_key(f.read())

# 5. Encrypt signature using RSA-OAEP-SHA256
encrypted = instructor_pub.encrypt(
    signature,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
)

# 6. Base64 encode
encrypted_b64 = base64.b64encode(encrypted).decode()

print("\nEncrypted Signature:")
print(encrypted_b64)
