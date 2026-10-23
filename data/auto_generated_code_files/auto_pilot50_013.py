import requests
import requests_cache
from bs4 import BeautifulSoup

class WebInteractor:
    def __init__(self, cache_name='web_cache', expire_after=300):
        self.session = requests_cache.CachedSession(cache_name, expire_after=expire_after)
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (compatible; WebInteractor/1.0)'})

    def get_page(self, url):
        response = self.session.get(url)
        response.raise_for_status()
        return response

    def parse_html(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        return soup

    def call_api(self, url, method='GET', data=None, json_data=None):
        if method.upper() == 'GET':
            response = self.session.get(url, params=data)
        elif method.upper() == 'POST':
            response = self.session.post(url, data=data, json=json_data)
        else:
            raise ValueError('Unsupported method')
        response.raise_for_status()
        return response.json()

    def authenticate_and_get(self, url, username, password):
        response = self.session.get(url, auth=(username, password))
        response.raise_for_status()
        return response

    def manage_cookies(self, url):
        self.session.get(f'{url}/cookies/set/sessioncookie/123456789')
        return self.session.cookies.get_dict()

def main():
    interactor = WebInteractor()
    
    print('--- HTML Parsing ---')
    resp = interactor.get_page('https://httpbin.org/html')
    soup = interactor.parse_html(resp.text)
    print(f"Page Title: {soup.h1.text if soup.h1 else 'No title'}")
    
    print('\n--- API Call ---')
    post_data = interactor.call_api('https://jsonplaceholder.typicode.com/posts/1')
    print(f"API Response Title: {post_data.get('title')}")
    
    print('\n--- Authentication ---')
    auth_resp = interactor.authenticate_and_get('https://httpbin.org/basic-auth/user/passwd', 'user', 'passwd')
    print(f"Authenticated: {auth_resp.json()}")
    
    print('\n--- Cookies ---')
    cookies = interactor.manage_cookies('https://httpbin.org')
    print(f"Cookies: {cookies}")

if __name__ == '__main__':
    main()
