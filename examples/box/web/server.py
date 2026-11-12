#!/usr/bin/env python3
"""Local web front end for a development box's Nucleus UI socket.

    server.py <ui-socket> [port]

Serves index.html on 127.0.0.1 and relays a fixed set of UI operations to the
socket. The relay holds no authority of its own: each request goes to the
socket as the owner's window (the label below), and the kernel decides every
call against what the composition grants that window. Only the operations in
ALLOWED are relayed.

No login. Whoever can reach this port can do what the owner's window can do
in this composition, so it listens on 127.0.0.1 only and is for a single
development machine. Do not bind it to a shared or public address.
"""
import json
import pathlib
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SOCKET = sys.argv[1] if len(sys.argv) > 1 else "run/ui.sock"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
PAGE = pathlib.Path(__file__).with_name("index.html")
LABEL = {"v": 1, "kind": "window", "account": "box-owner", "nickname": "box", "role": "owner"}
ALLOWED = {
    "whoami",
    "projects.list",
    "projects.create",
    "files.list",
    "files.download",
    "files.upload",
    "files.mkdir",
    "files.remove",
}
MAX_BODY = 2 * 1024 * 1024


def ui_call(payload):
    """One request on a fresh window connection: the label line, then the request."""
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(120)
    try:
        conn.connect(SOCKET)
        io = conn.makefile("rwb")
        io.write((json.dumps(LABEL) + "\n").encode())
        io.write((json.dumps({"id": 1, **payload}) + "\n").encode())
        io.flush()
        line = io.readline()
        if not line:
            return {"error": {"code": "service_error", "message": "the UI service closed the connection"}}
        return json.loads(line)
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, kind):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self):
        if self.path != "/api/ui":
            return self._send(404, b"not found", "text/plain; charset=utf-8")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            return self._send(413, b'{"error":{"code":"limit_exceeded","message":"bad body size"}}', "application/json")
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            return self._send(400, b'{"error":{"code":"invalid_input","message":"body is not JSON"}}', "application/json")
        if not isinstance(payload, dict) or payload.get("op") not in ALLOWED:
            return self._send(403, b'{"error":{"code":"permission_denied","message":"operation not relayed"}}', "application/json")
        try:
            reply = ui_call(payload)
        except OSError as e:
            reply = {"error": {"code": "unavailable", "message": f"UI socket: {e}"}}
        self._send(200, json.dumps(reply).encode(), "application/json")

    def log_message(self, fmt, *args):
        sys.stderr.write("web: " + (fmt % args) + "\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
