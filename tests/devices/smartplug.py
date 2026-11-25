"""SmartPlug: HTTPS, device-login handshake issuing tokens, status polling and command delivery.

Like many cheap plugs it does not verify server certificates, so it accepts Modigliani's CA.
"""

from __future__ import annotations

import http.client
import json
import random
import ssl
import time
from typing import Any

from tests.devices.base import Device
from tests.support.net import SniHTTPSConnection, Target

SERIAL = "SP-1A2B3C"
FACTORY_SECRET = "factory-pass-7"
FIRMWARE = "1.4.2"


class SmartPlug(Device):
    name = "smartplug"

    def __init__(self, target: Target, poll_interval: float = 0.5, status_interval: float = 1.0) -> None:
        super().__init__()
        self.target = target
        self.poll_interval = poll_interval
        self.status_interval = status_interval
        self.token: str | None = None
        self.token_expiry = 0.0
        self.started = time.time()
        self.conn: SniHTTPSConnection | None = None
        self.state = {"power": False, "watts": 0.0}
        self.clock_offset = 0.0

    def _ctx(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def request(self, method: str, path: str, body: Any = None, auth: bool = True) -> tuple[int, Any]:
        headers = {"Host": self.target.hostname, "User-Agent": f"AcmePlug/{FIRMWARE}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        for attempt in range(2):
            if self.conn is None:
                self.conn = SniHTTPSConnection(self.target, self._ctx())
            try:
                self.conn.request(method, path, body=data, headers=headers)
                resp = self.conn.getresponse()
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
            except (OSError, http.client.HTTPException) as exc:
                self.conn.close()
                self.conn = None
                if attempt:
                    raise ConnectionError(str(exc)) from exc
        raise ConnectionError("unreachable")

    def login(self) -> None:
        status, body = self.request(
            "POST", "/api/v1/auth/login", {"serial": SERIAL, "secret": FACTORY_SECRET}, auth=False
        )
        if status != 200 or not isinstance(body, dict) or "token" not in body:
            raise ConnectionError(f"login failed: {status}")
        self.token = str(body["token"])
        self.token_expiry = time.time() + float(body.get("expires_in", 60))
        self.health.authenticated = True

    def run(self) -> None:
        last_status = 0.0
        housekeeping_done = False
        while not self._stop.is_set():
            try:
                if self.token is None or time.time() > self.token_expiry - 5:
                    self.login()
                if not housekeeping_done:
                    status, body = self.request("GET", "/api/v1/time", auth=False)
                    if status == 200 and isinstance(body, dict):
                        self.clock_offset = float(body["epoch"]) - time.time()
                    self.request("GET", f"/api/v1/firmware?current={FIRMWARE}", auth=False)
                    housekeeping_done = True
                status, body = self.request("GET", f"/api/v1/devices/{SERIAL}/commands")
                if status == 401:
                    self.token = None
                    continue
                if status == 200 and isinstance(body, dict):
                    for cmd in body.get("commands", []):
                        if cmd.get("action") == "set_power" and isinstance(cmd.get("power"), bool):
                            with self.lock:
                                self.state["power"] = cmd["power"]
                            self.health.commands_applied += 1
                if time.time() - last_status >= self.status_interval:
                    with self.lock:
                        self.state["watts"] = round(random.uniform(38, 62), 1) if self.state["power"] else 0.0
                        report = {
                            "power": self.state["power"],
                            "watts": self.state["watts"],
                            "uptime": int(time.time() - self.started),
                        }
                    status, _ = self.request("POST", f"/api/v1/devices/{SERIAL}/status", report)
                    if status == 200:
                        self.health.ok()
                    elif status == 401:
                        self.token = None
                    last_status = time.time()
            except (ConnectionError, ValueError) as exc:
                self.health.error(str(exc))
                self.sleep(0.5)
            self.sleep(self.poll_interval)
        if self.conn:
            self.conn.close()
