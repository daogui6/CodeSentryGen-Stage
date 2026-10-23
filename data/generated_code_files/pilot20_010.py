import datetime
import hashlib
import hmac
import json
import urllib.parse
import urllib.request


class SimpleAWSClient:
    def __init__(self, access_key, secret_key, region, service):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service

    def _sign(self, key, message):
        return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()

    def _signature_key(self, date_stamp):
        k_date = self._sign(("AWS4" + self.secret_key).encode("utf-8"), date_stamp)
        k_region = self._sign(k_date, self.region)
        k_service = self._sign(k_region, self.service)
        return self._sign(k_service, "aws4_request")

    def post_json(self, endpoint, target, payload):
        body = json.dumps(payload).encode("utf-8")
        now = datetime.datetime.utcnow()
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")

        request = urllib.request.Request(endpoint, data=body, method="POST")
        request.add_header("Content-Type", "application/x-amz-json-1.1")
        request.add_header("X-Amz-Date", amz_date)
        request.add_header("X-Amz-Target", target)

        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))


if __name__ == "__main__":
    print("Simple low-level AWS client skeleton using built-in modules only.")
