"""Builders for synthetic captures used by the unit tests (no network needed)."""

from __future__ import annotations

import json
import struct
from typing import Any

from modigliani.capture.model import Capture, Direction, Endpoint, Flow, Segment, TlsInfo, TlsOutcome


def http_request(method: str, path: str, body: Any = None, headers: dict[str, str] | None = None) -> bytes:
    data = json.dumps(body).encode() if body is not None else b""
    head = [f"{method} {path} HTTP/1.1", "Host: api.vendor.example"]
    for k, v in (headers or {}).items():
        head.append(f"{k}: {v}")
    if body is not None:
        head += ["Content-Type: application/json", f"Content-Length: {len(data)}"]
    return ("\r\n".join(head) + "\r\n\r\n").encode() + data


def http_response(status: int, body: Any = None, chunked: bool = False) -> bytes:
    data = json.dumps(body).encode() if body is not None else b""
    head = [f"HTTP/1.1 {status} OK", "Content-Type: application/json"]
    if chunked:
        head.append("Transfer-Encoding: chunked")
        payload = f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n"
    else:
        head.append(f"Content-Length: {len(data)}")
        payload = data
    return ("\r\n".join(head) + "\r\n\r\n").encode() + payload


def _str(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">H", len(b)) + b


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mqtt_connect(
    client_id: str, username: str | None = None, password: str | None = None, level: int = 4, keepalive: int = 30
) -> bytes:
    flags = 0x02 | (0x80 if username else 0) | (0x40 if password else 0)
    body = _str("MQTT") + bytes([level, flags]) + struct.pack(">H", keepalive)
    if level == 5:
        body += b"\x00"
    body += _str(client_id)
    if username:
        body += _str(username)
    if password:
        body += _str(password)
    return b"\x10" + _varint(len(body)) + body


def mqtt_publish(topic: str, payload: bytes, qos: int = 0, pid: int = 1, level: int = 4, retain: bool = False) -> bytes:
    body = _str(topic) + (struct.pack(">H", pid) if qos else b"") + (b"\x00" if level == 5 else b"") + payload
    return bytes([0x30 | (qos << 1) | (1 if retain else 0)]) + _varint(len(body)) + body


def mqtt_subscribe(topic: str, qos: int = 1, pid: int = 1) -> bytes:
    body = struct.pack(">H", pid) + _str(topic) + bytes([qos])
    return b"\x82" + _varint(len(body)) + body


class FlowBuilder:
    def __init__(
        self,
        index: int,
        transport: str = "tcp",
        port: int = 443,
        hostname: str = "api.vendor.example",
        device: str = "dev",
        tls: TlsOutcome = TlsOutcome.ACCEPTED_LOCAL_CA,
    ) -> None:
        self.flow = Flow(
            index=index,
            device=device,
            transport=transport,  # type: ignore[arg-type]
            client=Endpoint(host="192.168.137.20", port=50000 + index),
            server=Endpoint(host="203.0.113.10", port=port),
            hostname=hostname,
            tls=TlsInfo(outcome=tls),
        )

    def up(self, ts: float, data: bytes) -> FlowBuilder:
        self.flow.segments.append(Segment.from_bytes(ts, Direction.UP, data))
        return self

    def down(self, ts: float, data: bytes) -> FlowBuilder:
        self.flow.segments.append(Segment.from_bytes(ts, Direction.DOWN, data))
        return self


def capture(*flows: Flow, name: str = "cap") -> Capture:
    return Capture(name=name, created=1_700_000_000.0, mode="proxy", flows=list(flows))
