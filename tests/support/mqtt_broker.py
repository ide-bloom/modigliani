"""A small MQTT 3.1.1/5 broker for tests.

It plays two roles: the thermostat vendor's cloud broker (with TLS and a publish hook for
the cloud logic) and the user's own broker that Home Assistant would use. It implements
CONNECT, PUBLISH (QoS 0/1), SUBSCRIBE with + and # wildcards, retained messages, PINGREQ and
DISCONNECT, which is everything the simulators and the server's discovery client use.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import struct
from collections.abc import Callable
from dataclasses import dataclass, field

from tests.support.net import LoopThread

PublishHook = Callable[["Session", str, bytes], None]


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _str(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">H", len(b)) + b


def topic_matches(pattern: str, topic: str) -> bool:
    p, t = pattern.split("/"), topic.split("/")
    for i, seg in enumerate(p):
        if seg == "#":
            return True
        if i >= len(t) or (seg != "+" and seg != t[i]):
            return False
    return len(p) == len(t)


@dataclass
class Session:
    client_id: str
    username: str | None
    password: bytes | None
    level: int
    writer: asyncio.StreamWriter
    subscriptions: dict[str, int] = field(default_factory=dict)
    next_id: int = 1


class Broker:
    def __init__(self, name: str = "broker", tls: ssl.SSLContext | None = None) -> None:
        self.name = name
        self.tls = tls
        self.sessions: dict[str, Session] = {}
        self.retained: dict[str, bytes] = {}
        self.hooks: list[PublishHook] = []
        self.connect_log: list[tuple[str, str | None]] = []
        self.loop = LoopThread(name)
        self.server: asyncio.Server | None = None
        self.port = 0

    def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        async def go() -> int:
            self.server = await asyncio.start_server(self._client, host, port, ssl=self.tls)
            return int(self.server.sockets[0].getsockname()[1])

        self.port = self.loop.run(go())
        return self.port

    def stop(self) -> None:
        async def go() -> None:
            if self.server:
                self.server.close()
            for s in list(self.sessions.values()):
                s.writer.close()

        try:
            self.loop.run(go())
        finally:
            self.loop.stop()

    def publish(self, topic: str, payload: bytes, qos: int = 0, retain: bool = False) -> None:
        """Publish from the broker side (the vendor cloud's own messages)."""
        self.loop.loop.call_soon_threadsafe(self._route, topic, payload, qos, retain)

    # ------------------------------------------------------------------ internals

    def _route(self, topic: str, payload: bytes, qos: int, retain: bool) -> None:
        if retain:
            if payload:
                self.retained[topic] = payload
            else:
                self.retained.pop(topic, None)
        for s in list(self.sessions.values()):
            granted = max((q for p, q in s.subscriptions.items() if topic_matches(p, topic)), default=None)
            if granted is not None:
                self._send_publish(s, topic, payload, min(qos, granted), False)

    def _send_publish(self, s: Session, topic: str, payload: bytes, qos: int, retain: bool) -> None:
        body = _str(topic)
        if qos:
            body += struct.pack(">H", s.next_id)
            s.next_id = s.next_id % 65535 + 1
        if s.level == 5:
            body += b"\x00"
        body += payload
        header = 0x30 | (qos << 1) | (1 if retain else 0)
        with contextlib.suppress(ConnectionError, RuntimeError):
            s.writer.write(bytes([header]) + _varint(len(body)) + body)

    async def _read_packet(self, reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
        b0 = (await reader.readexactly(1))[0]
        mult, length = 1, 0
        while True:
            b = (await reader.readexactly(1))[0]
            length += (b & 0x7F) * mult
            if not b & 0x80:
                break
            mult *= 128
        return b0 >> 4, b0 & 0x0F, await reader.readexactly(length)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session: Session | None = None
        try:
            ptype, _, body = await self._read_packet(reader)
            if ptype != 1:
                return
            pos = 2 + struct.unpack_from(">H", body, 0)[0]
            level = body[pos]
            flags = body[pos + 1]
            pos += 4
            if level == 5:
                plen, pos = self._read_varint(body, pos)
                pos += plen
            n = struct.unpack_from(">H", body, pos)[0]
            client_id = body[pos + 2 : pos + 2 + n].decode()
            pos += 2 + n
            if flags & 0x04:
                if level == 5:
                    plen, pos = self._read_varint(body, pos)
                    pos += plen
                for _ in range(2):
                    pos += 2 + struct.unpack_from(">H", body, pos)[0]
            username = password = None
            if flags & 0x80:
                n = struct.unpack_from(">H", body, pos)[0]
                username = body[pos + 2 : pos + 2 + n].decode()
                pos += 2 + n
            if flags & 0x40:
                n = struct.unpack_from(">H", body, pos)[0]
                password = body[pos + 2 : pos + 2 + n]
            session = Session(client_id, username, password, level, writer)
            old = self.sessions.get(client_id)
            if old is not None:
                old.writer.close()
            self.sessions[client_id] = session
            self.connect_log.append((client_id, username))
            writer.write(b"\x20\x03\x00\x00\x00" if level == 5 else b"\x20\x02\x00\x00")
            while True:
                ptype, flags, body = await self._read_packet(reader)
                if ptype == 3:
                    qos = (flags >> 1) & 3
                    tlen = struct.unpack_from(">H", body, 0)[0]
                    topic = body[2 : 2 + tlen].decode()
                    pos = 2 + tlen
                    pid = None
                    if qos:
                        pid = struct.unpack_from(">H", body, pos)[0]
                        pos += 2
                    if level == 5:
                        plen, pos = self._read_varint(body, pos)
                        pos += plen
                    payload = body[pos:]
                    if qos and pid is not None:
                        writer.write(
                            b"\x40\x02" + struct.pack(">H", pid)
                            if level != 5
                            else b"\x40\x03" + struct.pack(">H", pid) + b"\x00"
                        )
                    self._route(topic, payload, qos, bool(flags & 1))
                    for hook in self.hooks:
                        hook(session, topic, payload)
                elif ptype == 8:
                    pid = struct.unpack_from(">H", body, 0)[0]
                    pos = 2
                    if level == 5:
                        plen, pos = self._read_varint(body, pos)
                        pos += plen
                    codes = bytearray()
                    new: list[str] = []
                    while pos < len(body):
                        tlen = struct.unpack_from(">H", body, pos)[0]
                        topic = body[pos + 2 : pos + 2 + tlen].decode()
                        qos = body[pos + 2 + tlen] & 3
                        pos += 3 + tlen
                        session.subscriptions[topic] = min(qos, 1)
                        codes.append(min(qos, 1))
                        new.append(topic)
                    payload = struct.pack(">H", pid) + (b"\x00" if level == 5 else b"") + bytes(codes)
                    writer.write(b"\x90" + _varint(len(payload)) + payload)
                    for t, data in list(self.retained.items()):
                        if any(topic_matches(p, t) for p in new):
                            self._send_publish(session, t, data, 0, True)
                elif ptype == 10:
                    pid = struct.unpack_from(">H", body, 0)[0]
                    writer.write(b"\xb0\x02" + struct.pack(">H", pid))
                elif ptype == 12:
                    writer.write(b"\xd0\x00")
                elif ptype == 14:
                    break
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError, OSError, struct.error, IndexError):
            pass
        finally:
            if session is not None and self.sessions.get(session.client_id) is session:
                del self.sessions[session.client_id]
            writer.close()

    @staticmethod
    def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
        mult, value = 1, 0
        while True:
            b = data[pos]
            pos += 1
            value += (b & 0x7F) * mult
            if not b & 0x80:
                return value, pos
            mult *= 128
