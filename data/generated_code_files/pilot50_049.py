from pathlib import Path

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow


SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
]


def create_google_oauth_client(client_secret_file: Path, token_file: Path) -> Credentials:
    if token_file.exists():
        return Credentials.from_authorized_user_file(str(token_file), SCOPES)

    flow = InstalledAppFlow.from_client_secrets_file(
        str(client_secret_file),
        scopes=SCOPES,
    )

    credentials = flow.run_local_server(port=0)

    token_file.write_text(credentials.to_json(), encoding="utf-8")
    return credentials


if __name__ == "__main__":
    client_secret = Path("client_secret.json")
    token_path = Path("token.json")

    if not client_secret.exists():
        print("Place client_secret.json in the current directory before running.")
    else:
        creds = create_google_oauth_client(client_secret, token_path)
        print("Created credentials. Valid:", creds.valid)
