import argparse
import json
import os
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--heartbeat")
    parser.add_argument("--port", type=int)
    return parser.parse_args()


def run_child(heartbeat):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    path = Path(heartbeat)
    path.parent.mkdir(parents=True, exist_ok=True)
    counter = 0
    while True:
        counter += 1
        path.write_text(f"{counter}\n", encoding="utf-8")
        time.sleep(0.05)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/health":
            self.send_error(404)
            return
        body = json.dumps({"status": "ok", "child": "term-resistant"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


arguments = parse_args()
if arguments.child:
    if not arguments.heartbeat:
        raise SystemExit("--heartbeat is required in child mode")
    run_child(arguments.heartbeat)

if not arguments.heartbeat or not arguments.port:
    raise SystemExit("--heartbeat and --port are required")

child = subprocess.Popen(
    [
        sys.executable,
        os.path.abspath(__file__),
        "--child",
        "--heartbeat",
        arguments.heartbeat,
    ],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
    start_new_session=True,
)
print(f"term-resistant-child:{child.pid}", flush=True)
heartbeat_deadline = time.monotonic() + 2
while not Path(arguments.heartbeat).is_file():
    if child.poll() is not None:
        raise SystemExit("TERM-resistant child exited before creating its heartbeat")
    if time.monotonic() >= heartbeat_deadline:
        raise SystemExit("TERM-resistant child did not create its heartbeat")
    time.sleep(0.01)

running = True


def stop(_signum, _frame):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
server = HTTPServer(("127.0.0.1", arguments.port), Handler)
server.timeout = 0.1
print(f"listening:127.0.0.1:{arguments.port}", flush=True)
while running:
    server.handle_request()
server.server_close()
