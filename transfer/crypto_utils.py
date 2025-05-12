import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def generate_rsa_key_pair():
    """Generate an RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return {
        "private_key": private_pem.decode("utf-8"),
        "public_key": public_pem.decode("utf-8"),
    }


def encrypt_file_with_aes(file_data):
    """Encrypt file data with AES-256-GCM"""
    # Generate a random AES key
    aes_key = os.urandom(32)  # 256 bits

    # Generate a random IV
    iv = os.urandom(12)

    # Encrypt the file
    cipher = AESGCM(aes_key)
    encrypted_data = cipher.encrypt(iv, file_data, None)

    return {"aes_key": aes_key, "iv": iv, "encrypted_data": encrypted_data}


def decrypt_file_with_aes(encrypted_data, aes_key, iv):
    """Decrypt file data with AES-256-GCM"""
    cipher = AESGCM(aes_key)
    decrypted_data = cipher.decrypt(iv, encrypted_data, None)

    return decrypted_data


def encrypt_aes_key_with_rsa(aes_key, public_key_pem):
    """Encrypt an AES key with an RSA public key"""
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))

    # Encrypt the AES key
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return encrypted_key


def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem):
    """Decrypt an AES key with an RSA private key"""
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )

    # Decrypt the AES key
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return decrypted_key


def calculate_file_hash(file_data):
    """Calculate SHA-256 hash of a file"""
    return hashlib.sha256(file_data).hexdigest()


def verify_file_hash(file_data, expected_hash):
    """Verify the SHA-256 hash of a file"""
    actual_hash = calculate_file_hash(file_data)
    return actual_hash == expected_hash


def encrypt_private_key(private_key_pem, password):
    """Encrypt a private key with a password"""
    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Generate a random IV
    iv = os.urandom(12)

    # Encrypt the private key
    cipher = AESGCM(key)
    encrypted_key = cipher.encrypt(iv, private_key_pem.encode("utf-8"), None)

    return {"salt": salt, "iv": iv, "encrypted_key": encrypted_key}


def decrypt_private_key(encrypted_data, salt, iv, password):
    """Decrypt a private key with a password"""
    # Derive the key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Decrypt the private key
    cipher = AESGCM(key)
    decrypted_key = cipher.decrypt(iv, encrypted_data, None)

    return decrypted_key.decode("utf-8")
