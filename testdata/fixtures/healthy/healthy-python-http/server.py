import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--port", type=int, default=8080)
    return parser.parse_args()


class Handler(BaseHTTPRequestHandler):
    output_path = None

    def send_json(self, status, payload):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
            return
        self.send_json(404, {"error": "not-found"})

    def do_POST(self):
        if self.path != "/echo":
            self.send_json(404, {"error": "not-found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(content_length)

        try:
            payload = json.loads(request_body)
        except json.JSONDecodeError:
            self.send_json(400, {"error": "invalid-json"})
            return

        result = {"received": payload, "runtime": "python"}
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(
            f"{json.dumps(result, indent=2, sort_keys=True)}\n",
            encoding="utf-8",
        )
        self.send_json(200, result)

    def log_message(self, format_string, *args):
        print(f"http:{format_string % args}", flush=True)


if __name__ == "__main__":
    arguments = parse_args()
    Handler.output_path = Path(arguments.output)
    server = HTTPServer(("127.0.0.1", arguments.port), Handler)
    print(f"listening:127.0.0.1:{arguments.port}", flush=True)
    server.serve_forever()
