import datetime as dt
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization


@dataclass
class TokenClaims:
    subject: str
    issuer: str
    audience: str
    expires_in_seconds: int = 3600

    def to_payload(self) -> dict[str, Any]:
        now = dt.datetime.now(tz=dt.UTC)

        return {
            "sub": self.subject,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + dt.timedelta(seconds=self.expires_in_seconds),
        }


def load_private_key(path: str, password: bytes | None = None):
    with open(path, "rb") as file:
        return serialization.load_pem_private_key(file.read(), password=password)


def load_public_key(path: str):
    with open(path, "rb") as file:
        return serialization.load_pem_public_key(file.read())


def create_hs256_token(claims: TokenClaims, secret: str) -> str:
    return jwt.encode(claims.to_payload(), secret, algorithm="HS256")


def verify_hs256_token(token: str, secret: str, audience: str, issuer: str) -> dict[str, Any]:
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience=audience,
        issuer=issuer,
    )


def create_rs256_token(claims: TokenClaims, private_key_path: str) -> str:
    private_key = load_private_key(private_key_path)
    return jwt.encode(claims.to_payload(), private_key, algorithm="RS256")


def verify_rs256_token(token: str, public_key_path: str, audience: str, issuer: str) -> dict[str, Any]:
    public_key = load_public_key(public_key_path)
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )


if __name__ == "__main__":
    claims = TokenClaims(
        subject="user-123",
        issuer="example-service",
        audience="example-client",
    )

    secret_key = "replace-this-demo-secret"
    token = create_hs256_token(claims, secret_key)
    print("Generated token:", token)

    payload = verify_hs256_token(
        token,
        secret_key,
        audience="example-client",
        issuer="example-service",
    )

    print("Verified payload:", payload)
