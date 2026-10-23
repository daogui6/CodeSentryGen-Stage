import urllib.request
import urllib.parse
import json
import hashlib
import hmac
import datetime

class AWSClient:
    def __init__(self, service, region, access_key, secret_key):
        self.service = service
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.host = f"{service}.{region}.amazonaws.com"

    def _sign(self, key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def _get_signature_key(self, date_stamp):
        k_date = self._sign(('AWS4' + self.secret_key).encode('utf-8'), date_stamp)
        k_region = self._sign(k_date, self.region)
        k_service = self._sign(k_region, self.service)
        k_signing = self._sign(k_service, 'aws4_request')
        return k_signing

    def make_request(self, method, path, payload=None, query_params=None):
        t = datetime.datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        canonical_uri = urllib.parse.quote(path, safe='/')
        
        canonical_querystring = ''
        if query_params:
            sorted_params = sorted(query_params.items())
            canonical_querystring = '&'.join([f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(str(v), safe='')}" for k, v in sorted_params])

        payload_str = json.dumps(payload) if payload else ''
        payload_hash = hashlib.sha256(payload_str.encode('utf-8')).hexdigest()

        headers_to_sign = {
            'host': self.host,
            'x-amz-date': amz_date,
            'x-amz-content-sha256': payload_hash
        }
        if payload:
            headers_to_sign['content-type'] = 'application/x-amz-json-1.1'

        signed_headers = ';'.join(sorted(headers_to_sign.keys()))
        canonical_headers = ''.join([f"{k}:{v}\n" for k, v in sorted(headers_to_sign.items())])

        canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        signing_key = self._get_signature_key(date_stamp)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        authorization_header = f"{algorithm} Credential={self.access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

        url = f"https://{self.host}{canonical_uri}"
        if canonical_querystring:
            url += f"?{canonical_querystring}"

        req_headers = {
            'Authorization': authorization_header,
            'x-amz-date': amz_date,
            'x-amz-content-sha256': payload_hash,
            'Host': self.host
        }
        if payload:
            req_headers['Content-Type'] = 'application/x-amz-json-1.1'

        req = urllib.request.Request(url, data=payload_str.encode('utf-8') if payload else None, headers=req_headers, method=method)
        
        try:
            with urllib.request.urlopen(req) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode('utf-8'))
