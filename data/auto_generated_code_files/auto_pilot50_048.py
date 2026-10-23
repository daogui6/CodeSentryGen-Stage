import requests
from requests_oauthlib import OAuth1Session

def make_authenticated_request():
    client_key = 'your_client_key'
    client_secret = 'your_client_secret'
    resource_owner_key = 'your_resource_owner_key'
    resource_owner_secret = 'your_resource_owner_secret'
    
    oauth_session = OAuth1Session(
        client_key,
        client_secret=client_secret,
        resource_owner_key=resource_owner_key,
        resource_owner_secret=resource_owner_secret
    )
    
    url = 'https://api.example.com/v1/resource'
    response = oauth_session.get(url)
    
    if response.status_code == 200:
        print('Success:', response.json())
    else:
        print('Failed:', response.status_code, response.text)

if __name__ == '__main__':
    make_authenticated_request()
