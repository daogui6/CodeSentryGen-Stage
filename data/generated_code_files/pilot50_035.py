from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_symmetric_key() -> bytes:
    return Fernet.generate_key()


def encrypt_with_fernet(key: bytes, plaintext: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.encrypt(plaintext)


def decrypt_with_fernet(key: bytes, token: bytes) -> bytes:
    cipher = Fernet(key)
    return cipher.decrypt(token)


def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def export_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


if __name__ == "__main__":
    message = b"important message"

    symmetric_key = generate_symmetric_key()
    encrypted = encrypt_with_fernet(symmetric_key, message)
    decrypted = decrypt_with_fernet(symmetric_key, encrypted)

    print("Encrypted token:", encrypted)
    print("Decrypted message:", decrypted)

    private_key = generate_rsa_private_key()
    public_key = private_key.public_key()
    signature = sign_message(private_key, message)

    print("Signature valid:", verify_signature(public_key, message, signature))
    print(export_public_key(public_key).decode("utf-8"))
