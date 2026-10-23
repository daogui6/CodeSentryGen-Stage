from google.oauth2.credentials import Credentials

def create_oauth2_client():
    token = 'your_access_token'
    refresh_token = 'your_refresh_token'
    token_uri = 'https://oauth2.googleapis.com/token'
    client_id = 'your_client_id'
    client_secret = 'your_client_secret'
    
    creds = Credentials(
        token=token,
        refresh_token=refresh_token,
        token_uri=token_uri,
        client_id=client_id,
        client_secret=client_secret
    )
    return creds

if __name__ == '__main__':
    credentials = create_oauth2_client()
    print("OAuth2 client created successfully.")
