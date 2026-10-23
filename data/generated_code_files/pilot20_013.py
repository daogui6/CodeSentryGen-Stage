import requests
import requests_cache
from bs4 import BeautifulSoup


class WebClient:
    def __init__(self, cache_name="web_cache", timeout=10):
        self.session = requests_cache.CachedSession(cache_name, expire_after=300)
        self.timeout = timeout

    def get(self, url, **kwargs):
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        return self.session.post(url, data=data, json=json, timeout=self.timeout, **kwargs)

    def get_json(self, url, **kwargs):
        response = self.get(url, **kwargs)
        response.raise_for_status()
        return response.json()

    def parse_html(self, url, **kwargs):
        response = self.get(url, **kwargs)
        response.raise_for_status()
        return BeautifulSoup(response.text, "html.parser")

    def set_auth_token(self, token):
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def set_cookie(self, name, value):
        self.session.cookies.set(name, value)


if __name__ == "__main__":
    client = WebClient()
    soup = client.parse_html("https://example.com")
    print(soup.title.string if soup.title else "No title")
