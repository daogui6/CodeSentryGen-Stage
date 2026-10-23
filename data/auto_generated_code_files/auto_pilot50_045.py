import hmac
import hashlib
import base64
import time
import uuid
import urllib.parse
import requests

def percent_encode(s):
    return urllib.parse.quote(str(s), safe='')

def generate_oauth_signature(method, url, params, consumer_key, consumer_secret, token=None, token_secret=None):
    oauth_params = {
        'oauth_consumer_key': consumer_key,
        'oauth_nonce': uuid.uuid4().hex,
        'oauth_signature_method': 'HMAC-SHA1',
        'oauth_timestamp': str(int(time.time())),
        'oauth_version': '1.0'
    }
    if token:
        oauth_params['oauth_token'] = token

    all_params = {}
    all_params.update(params)
    all_params.update(oauth_params)

    sorted_params = sorted(all_params.items(), key=lambda x: x[0])
    param_string = '&'.join([percent_encode(k) + '=' + percent_encode(v) for k, v in sorted_params])

    parsed_url = urllib.parse.urlparse(url)
    base_url = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path
    base_string = method.upper() + '&' + percent_encode(base_url) + '&' + percent_encode(param_string)

    signing_key = percent_encode(consumer_secret) + '&' + percent_encode(token_secret or '')

    hashed = hmac.new(signing_key.encode('utf-8'), base_string.encode('utf-8'), hashlib.sha1)
    signature = base64.b64encode(hashed.digest()).decode('utf-8')

    oauth_params['oauth_signature'] = signature

    auth_header = 'OAuth ' + ', '.join([percent_encode(k) + '="' + percent_encode(v) + '"' for k, v in sorted(oauth_params.items())])
    
    return auth_header

def oauth_request(method, url, consumer_key, consumer_secret, token=None, token_secret=None, params=None, data=None, headers=None):
    if params is None:
        params = {}
    if headers is None:
        headers = {}
        
    sign_params = dict(params)
    if data and isinstance(data, dict):
        sign_params.update(data)
        
    auth_header = generate_oauth_signature(method, url, sign_params, consumer_key, consumer_secret, token, token_secret)
    headers['Authorization'] = auth_header
    
    response = requests.request(method, url, params=params, data=data, headers=headers)
    return response
