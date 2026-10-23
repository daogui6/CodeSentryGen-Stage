import urllib3


http = urllib3.PoolManager(
    retries=0,
)

response = http.request(
    "GET",
    "https://example.com/start",
)