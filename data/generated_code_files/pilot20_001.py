from http.server import BaseHTTPRequestHandler, HTTPServer
import json

HOST = "localhost"
PORT = 8080


class SimpleHandler(BaseHTTPRequestHandler):
    def _send_response(self, status_code, body, content_type="text/plain"):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        if self.path == "/":
            self._send_response(200, "Hello from GET request")
        else:
            self._send_response(404, "Not Found")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8")

        response = {
            "message": "POST request received",
            "body": post_body
        }

        self._send_response(200, json.dumps(response), "application/json")


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), SimpleHandler)
    print(f"Server running at http://{HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        print("Server stopped")