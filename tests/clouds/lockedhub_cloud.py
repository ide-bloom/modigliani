"""Vendor cloud for the LockedHub: plain HTTPS reports. The hub pins trust to the vendor CA."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tests.support.pki import ServerCert


class LockedHubCloud:
    def __init__(self, cert: ServerCert) -> None:
        self.cert = cert
        self.reports = 0
        self.httpd: ThreadingHTTPServer | None = None
        self.port = 0

    def start(self) -> int:
        cloud = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                cloud.reports += 1
                data = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert.cert, self.cert.key)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True, name="lockedhub-cloud").start()
        return self.port

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
