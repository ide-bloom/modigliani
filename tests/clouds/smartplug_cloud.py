"""Vendor cloud for the SmartPlug: HTTPS REST with a device-login handshake and command polling."""

from __future__ import annotations

import json
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from tests.support.pki import ServerCert

TOKEN_LIFETIME = 3600


class SmartPlugCloud:
    def __init__(self, cert: ServerCert) -> None:
        self.cert = cert
        self.tokens: dict[str, tuple[str, float]] = {}
        self.pending: dict[str, list[dict[str, Any]]] = {}
        self.last_status: dict[str, dict[str, Any]] = {}
        self.seq = 0
        self.lock = threading.Lock()
        self.httpd: ThreadingHTTPServer | None = None
        self.port = 0

    # ------------------------------------------------------------------ the vendor phone app

    def app_set_power(self, serial: str, on: bool) -> None:
        with self.lock:
            self.seq += 1
            self.pending.setdefault(serial, []).append({"seq": self.seq, "action": "set_power", "power": on})

    # ------------------------------------------------------------------ server

    def start(self) -> int:
        cloud = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def _json(self, status: int, body: Any) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self) -> Any:
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"null")

            def _serial(self) -> str | None:
                auth = self.headers.get("Authorization", "")
                token = auth.removeprefix("Bearer ").strip()
                with cloud.lock:
                    entry = cloud.tokens.get(token)
                if entry is None or entry[1] < time.time():
                    return None
                return entry[0]

            def do_POST(self) -> None:
                path = urlsplit(self.path).path
                body = self._body()
                if path == "/api/v1/auth/login":
                    if not isinstance(body, dict) or not body.get("serial") or not body.get("secret"):
                        self._json(400, {"error": "bad request"})
                        return
                    token = secrets.token_hex(16)
                    with cloud.lock:
                        cloud.tokens[token] = (body["serial"], time.time() + TOKEN_LIFETIME)
                    self._json(200, {"token": token, "expires_in": TOKEN_LIFETIME})
                    return
                serial = self._serial()
                if serial is None:
                    self._json(401, {"error": "unauthorized"})
                    return
                if path == f"/api/v1/devices/{serial}/status":
                    with cloud.lock:
                        cloud.last_status[serial] = body
                    self._json(200, {"ok": True})
                    return
                self._json(404, {"error": "not found"})

            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                if parts.path == "/api/v1/time":
                    self._json(200, {"epoch": int(time.time())})
                    return
                if parts.path == "/api/v1/firmware":
                    current = parse_qs(parts.query).get("current", ["0"])[0]
                    self._json(200, {"update": False, "latest": current, "url": ""})
                    return
                serial = self._serial()
                if serial is None:
                    self._json(401, {"error": "unauthorized"})
                    return
                if parts.path == f"/api/v1/devices/{serial}/commands":
                    with cloud.lock:
                        cmds = cloud.pending.pop(serial, [])
                    self._json(200, {"commands": cmds})
                    return
                self._json(404, {"error": "not found"})

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert.cert, self.cert.key)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="smartplug-cloud").start()
        return self.port

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
