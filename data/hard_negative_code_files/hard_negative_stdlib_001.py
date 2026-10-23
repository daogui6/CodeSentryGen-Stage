import json
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

def main():
    data = {"ok": True}
    print(json.dumps(data))
    print(Path(".").resolve())

if __name__ == "__main__":
    main()
