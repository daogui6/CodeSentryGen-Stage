import os
import shutil
import requests
import certifi


MOZILLA_CA_BUNDLE_URL = "https://curl.se/ca/cacert.pem"


def download_ca_bundle(output_path):
    response = requests.get(MOZILLA_CA_BUNDLE_URL, timeout=30)
    response.raise_for_status()

    with open(output_path, "wb") as f:
        f.write(response.content)

    return output_path


def install_ca_bundle(downloaded_path, trusted_ca_dir):
    os.makedirs(trusted_ca_dir, exist_ok=True)
    target_path = os.path.join(trusted_ca_dir, "mozilla-cacert.pem")
    shutil.copy2(downloaded_path, target_path)
    return target_path


if __name__ == "__main__":
    local_file = "cacert.pem"
    trusted_dir = os.path.dirname(certifi.where())

    try:
        downloaded = download_ca_bundle(local_file)
        installed = install_ca_bundle(downloaded, trusted_dir)
        print(f"CA bundle installed to: {installed}")
    except Exception as e:
        print(f"Failed to install CA bundle: {e}")
