from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import base64

def symmetric_encrypt_decrypt(data: bytes):
    key = Fernet.generate_key()
    f = Fernet(key)
    encrypted_data = f.encrypt(data)
    decrypted_data = f.decrypt(encrypted_data)
    return encrypted_data, decrypted_data

def sign_and_verify(data: bytes):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signature = private_key.sign(data)
    public_key.verify(signature, data)
    return signature

if __name__ == "__main__":
    message = b"Secret message for CodeSentry-Gen"
    enc_data, dec_data = symmetric_encrypt_decrypt(message)
    print(f"Original: {message}")
    print(f"Encrypted: {enc_data}")
    print(f"Decrypted: {dec_data}")
    sig = sign_and_verify(message)
    print(f"Signature: {base64.b64encode(sig).decode()}")
    print("Signature verified successfully.")
