from pathlib import Path
from typing import Any

from google.oauth2 import service_account
from googleapiclient.discovery import build


SCOPES = [
    "https://www.googleapis.com/auth/drive.metadata.readonly",
    "https://www.googleapis.com/auth/spreadsheets.readonly",
    "https://www.googleapis.com/auth/presentations.readonly",
]


def load_credentials(service_account_file: Path):
    return service_account.Credentials.from_service_account_file(
        str(service_account_file),
        scopes=SCOPES,
    )


def create_service(api_name: str, api_version: str, credentials):
    return build(api_name, api_version, credentials=credentials)


def create_google_services(service_account_file: Path) -> dict[str, Any]:
    credentials = load_credentials(service_account_file)

    return {
        "drive": create_service("drive", "v3", credentials),
        "sheets": create_service("sheets", "v4", credentials),
        "slides": create_service("slides", "v1", credentials),
    }


if __name__ == "__main__":
    credentials_file = Path("service_account.json")

    if not credentials_file.exists():
        print("Place a service_account.json file in this directory before running.")
    else:
        services = create_google_services(credentials_file)
        print("Created services:", ", ".join(services.keys()))
