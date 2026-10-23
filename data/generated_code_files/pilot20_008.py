import threading
import requests
from requests.adapters import HTTPAdapter


class ThreadSafeSessionManager:
    def __init__(self, pool_connections=10, pool_maxsize=20):
        self.local = threading.local()
        self.pool_connections = pool_connections
        self.pool_maxsize = pool_maxsize

    def get_session(self):
        if not hasattr(self.local, "session"):
            session = requests.Session()
            adapter = HTTPAdapter(
                pool_connections=self.pool_connections,
                pool_maxsize=self.pool_maxsize
            )
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self.local.session = session
        return self.local.session

    def get(self, url, **kwargs):
        session = self.get_session()
        return session.get(url, **kwargs)

    def post_file(self, url, file_path, field_name="file", **kwargs):
        session = self.get_session()
        with open(file_path, "rb") as f:
            files = {field_name: f}
            return session.post(url, files=files, **kwargs)


if __name__ == "__main__":
    manager = ThreadSafeSessionManager()
    response = manager.get("https://example.com", timeout=10)
    print(response.status_code)
