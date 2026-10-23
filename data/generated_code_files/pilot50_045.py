import base64
import hashlib
import hmac
import time
import urllib.parse
from dataclasses import dataclass

import requests


@dataclass
class OAuthCredentials:
    consumer_key: str
    consumer_secret: str
    token: str
    token_secret: str


def percent_encode(value: str) -> str:
    return urllib.parse.quote(value, safe="~")


def build_signature_base_string(
    method: str,
    url: str,
    parameters: dict[str, str],
) -> str:
    encoded_params = [
        (percent_encode(key), percent_encode(value))
        for key, value in parameters.items()
    ]
    encoded_params.sort()

    parameter_string = "&".join(f"{key}={value}" for key, value in encoded_params)

    parts = [
        method.upper(),
        percent_encode(url),
        percent_encode(parameter_string),
    ]

    return "&".join(parts)


def sign_request(
    method: str,
    url: str,
    credentials: OAuthCredentials,
    extra_parameters: dict[str, str] | None = None,
) -> str:
    parameters = {
        "oauth_consumer_key": credentials.consumer_key,
        "oauth_token": credentials.token,
        "oauth_nonce": hashlib.sha256(str(time.time()).encode()).hexdigest(),
        "oauth_timestamp": str(int(time.time())),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_version": "1.0",
    }

    if extra_parameters:
        parameters.update(extra_parameters)

    base_string = build_signature_base_string(method, url, parameters)
    signing_key = f"{percent_encode(credentials.consumer_secret)}&{percent_encode(credentials.token_secret)}"

    digest = hmac.new(
        signing_key.encode("utf-8"),
        base_string.encode("utf-8"),
        hashlib.sha1,
    ).digest()

    parameters["oauth_signature"] = base64.b64encode(digest).decode("utf-8")

    authorization_values = [
        f'{percent_encode(key)}="{percent_encode(value)}"'
        for key, value in parameters.items()
        if key.startswith("oauth_")
    ]

    return "OAuth " + ", ".join(authorization_values)


def get_with_oauth(url: str, credentials: OAuthCredentials) -> requests.Response:
    auth_header = sign_request("GET", url, credentials)
    return requests.get(url, headers={"Authorization": auth_header}, timeout=10)


if __name__ == "__main__":
    demo_credentials = OAuthCredentials(
        consumer_key="consumer-key",
        consumer_secret="consumer-secret",
        token="access-token",
        token_secret="token-secret",
    )

    header = sign_request("GET", "https://api.example.com/resource", demo_credentials)
    print(header)
