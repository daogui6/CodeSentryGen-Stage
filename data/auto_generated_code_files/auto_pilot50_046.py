import jwt
from typing import Any, Dict

class JWTManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key

    def generate_hs256(self, payload: Dict[str, Any]) -> str:
        """Generate a JWS token using HMAC SHA-256."""
        return jwt.encode(payload, self.secret_key, algorithm='HS256')

    def verify_hs256(self, token: str) -> Dict[str, Any]:
        """Verify a JWS token using HMAC SHA-256."""
        return jwt.decode(token, self.secret_key, algorithms=['HS256'])

    def generate_jwe_rsa_oaep(self, payload: Dict[str, Any], public_key: str) -> str:
        """Generate a JWE token using RSA-OAEP key encryption."""
        return jwt.encode(payload, public_key, algorithm='RSA-OAEP', encryption='A256GCM')

    def verify_jwe_rsa_oaep(self, token: str, private_key: str) -> Dict[str, Any]:
        """Verify and decrypt a JWE token using RSA-OAEP."""
        return jwt.decode(token, private_key, algorithms=['RSA-OAEP'])

    def generate_jwe_rsa1_5(self, payload: Dict[str, Any], public_key: str) -> str:
        """Generate a JWE token using RSA1_5 key encryption."""
        return jwt.encode(payload, public_key, algorithm='RSA1_5', encryption='A256GCM')

    def verify_jwe_rsa1_5(self, token: str, private_key: str) -> Dict[str, Any]:
        """Verify and decrypt a JWE token using RSA1_5."""
        return jwt.decode(token, private_key, algorithms=['RSA1_5'])
