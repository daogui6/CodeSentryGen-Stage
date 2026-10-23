import requests
from oauthlib.oauth2 import BackendApplicationClient
from requests_oauthlib import OAuth2Session


def create_oauth_session(client_id: str, token_url: str, client_secret: str) -> OAuth2Session:
    client = BackendApplicationClient(client_id=client_id)
    session = OAuth2Session(client=client)

    session.fetch_token(
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
    )

    return session


def get_json(session: OAuth2Session, url: str) -> dict:
    response = session.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    print("Configure client_id, token_url, and client_secret before running this script.")
