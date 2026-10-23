import requests
import os

def download_and_save_ca_bundle():
    url = "https://curl.se/ca/cacert.pem"
    response = requests.get(url)
    response.raise_for_status()
    
    ca_dir = "/etc/ssl/certs"
    if not os.path.exists(ca_dir):
        ca_dir = "/usr/local/share/ca-certificates"
        
    save_path = os.path.join(ca_dir, "mozilla-ca-bundle.crt")
    
    with open(save_path, "wb") as f:
        f.write(response.content)
        
    print(f"CA bundle successfully saved to {save_path}")

if __name__ == "__main__":
    download_and_save_ca_bundle()
