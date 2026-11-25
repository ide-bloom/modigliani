"""Wire decoders for the protocols Modigliani understands.

They are deliberately tolerant: captures can start mid-stream or end mid-message, so a
decoder stops at the first unparseable byte and reports what it decoded so far.
"""

from __future__ import annotations

import gzip
import struct
import zlib
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")


class DecodeError(ValueError):
    pass


# --------------------------------------------------------------------------- HTTP/1.x


@dataclass
class HttpRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes
    offset: int = 0
    end: int = 0

    @property
    def path(self) -> str:
        return urlsplit(self.target).path or "/"

    @property
    def query(self) -> dict[str, list[str]]:
        return parse_qs(urlsplit(self.target).query, keep_blank_values=True)

    def header(self, name: str) -> str | None:
        return _hget(self.headers, name.lower())


@dataclass
class HttpResponse:
    status: int
    reason: str
    version: str
    headers: list[tuple[str, str]]
    body: bytes
    offset: int = 0
    end: int = 0

    def header(self, name: str) -> str | None:
        return _hget(self.headers, name.lower())


def _hget(headers: list[tuple[str, str]], name: str) -> str | None:
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def _parse_head(data: bytes, pos: int) -> tuple[str, list[tuple[str, str]], int]:
    end = data.find(b"\r\n\r\n", pos)
    if end < 0:
        raise DecodeError("incomplete HTTP head")
    lines = data[pos:end].decode("latin-1").split("\r\n")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            raise DecodeError(f"bad header line {line!r}")
        k, v = line.split(":", 1)
        headers.append((k.strip(), v.strip()))
    return lines[0], headers, end + 4


def _read_body(data: bytes, pos: int, headers: list[tuple[str, str]], *, until_close: bool) -> tuple[bytes, int]:
    te = (_hget(headers, "transfer-encoding") or "").lower()
    if "chunked" in te:
        body = bytearray()
        while True:
            nl = data.find(b"\r\n", pos)
            if nl < 0:
                raise DecodeError("incomplete chunk size")
            size = int(data[pos:nl].split(b";")[0].strip() or b"0", 16)
            pos = nl + 2
            if size == 0:
                trailer_end = data.find(b"\r\n", pos)
                pos = (trailer_end + 2) if trailer_end >= 0 else len(data)
                break
            if pos + size > len(data):
                raise DecodeError("incomplete chunk")
            body += data[pos : pos + size]
            pos += size + 2
        raw = bytes(body)
    elif (cl := _hget(headers, "content-length")) is not None:
        n = int(cl)
        if pos + n > len(data):
            raise DecodeError("incomplete body")
        raw, pos = data[pos : pos + n], pos + n
    elif until_close:
        raw, pos = data[pos:], len(data)
    else:
        raw = b""
    enc = (_hget(headers, "content-encoding") or "").lower()
    try:
        if enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            raw = zlib.decompress(raw)
    except (OSError, zlib.error):
        pass
    return raw, pos


def is_ws_upgrade(headers: list[tuple[str, str]]) -> bool:
    return (_hget(headers, "upgrade") or "").lower() == "websocket"


def decode_http_requests(data: bytes) -> list[HttpRequest]:
    out: list[HttpRequest] = []
    pos = 0
    while pos < len(data) and data.startswith(HTTP_METHODS, pos):
        try:
            start_line, headers, body_pos = _parse_head(data, pos)
            method, target, version = start_line.split(" ", 2)
            body, end = _read_body(data, body_pos, headers, until_close=False)
        except (DecodeError, ValueError):
            break
        out.append(HttpRequest(method, target, version, headers, body, pos, end))
        pos = end
        if is_ws_upgrade(headers):
            break
    return out


def decode_http_responses(data: bytes, request_methods: list[str]) -> list[HttpResponse]:
    out: list[HttpResponse] = []
    pos = 0
    i = 0
    while pos < len(data) and data.startswith(b"HTTP/", pos):
        try:
            start_line, headers, body_pos = _parse_head(data, pos)
            parts = start_line.split(" ", 2)
            version, status = parts[0], int(parts[1])
            reason = parts[2] if len(parts) > 2 else ""
            no_body = (
                status < 200 or status in (204, 304) or (i < len(request_methods) and request_methods[i] == "HEAD")
            )
            if no_body:
                body, end = b"", body_pos
            else:
                body, end = _read_body(data, body_pos, headers, until_close=True)
        except (DecodeError, ValueError):
            break
        out.append(HttpResponse(status, reason, version, headers, body, pos, end))
        pos = end
        if status != 100:
            i += 1
        if status == 101:
            break
    return out


# --------------------------------------------------------------------------- WebSocket


@dataclass
class WsMessage:
    opcode: int  # 1 text, 2 binary, 8 close, 9 ping, 10 pong
    payload: bytes
    offset: int


def decode_ws_frames(data: bytes) -> list[WsMessage]:
    out: list[WsMessage] = []
    pos = 0
    partial: bytearray | None = None
    partial_op = 0
    partial_off = 0
    while pos + 2 <= len(data):
        start = pos
        b0, b1 = data[pos], data[pos + 1]
        fin, opcode = bool(b0 & 0x80), b0 & 0x0F
        masked, length = bool(b1 & 0x80), b1 & 0x7F
        pos += 2
        if length == 126:
            if pos + 2 > len(data):
                break
            length = struct.unpack_from(">H", data, pos)[0]
            pos += 2
        elif length == 127:
            if pos + 8 > len(data):
                break
            length = struct.unpack_from(">Q", data, pos)[0]
            pos += 8
        mask = b""
        if masked:
            mask = data[pos : pos + 4]
            pos += 4
        if pos + length > len(data):
            break
        payload = data[pos : pos + length]
        if masked:
            payload = bytes(c ^ mask[j % 4] for j, c in enumerate(payload))
        pos += length
        if opcode == 0 and partial is not None:
            partial += payload
            if fin:
                out.append(WsMessage(partial_op, bytes(partial), partial_off))
                partial = None
        elif not fin and opcode in (1, 2):
            partial, partial_op, partial_off = bytearray(payload), opcode, start
        else:
            out.append(WsMessage(opcode, payload, start))
    return out


def encode_ws_frame(opcode: int, payload: bytes, mask: bytes | None = None) -> bytes:
    """Produce a single unfragmented frame (used by tests and the replay tester)."""
    head = bytearray([0x80 | opcode])
    mbit = 0x80 if mask else 0
    n = len(payload)
    if n < 126:
        head.append(mbit | n)
    elif n < 65536:
        head.append(mbit | 126)
        head += struct.pack(">H", n)
    else:
        head.append(mbit | 127)
        head += struct.pack(">Q", n)
    if mask:
        head += mask
        payload = bytes(c ^ mask[j % 4] for j, c in enumerate(payload))
    return bytes(head) + payload


# --------------------------------------------------------------------------- MQTT

MQTT_TYPES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}


@dataclass
class MqttPacket:
    type: str
    offset: int
    flags: int = 0
    # CONNECT
    protocol_level: int = 0
    client_id: str = ""
    username: str | None = None
    password: bytes | None = None
    keepalive: int = 0
    clean_start: bool = False
    # PUBLISH
    topic: str = ""
    payload: bytes = b""
    qos: int = 0
    retain: bool = False
    packet_id: int | None = None
    # SUBSCRIBE / UNSUBSCRIBE
    subscriptions: list[tuple[str, int]] = field(default_factory=list)
    # CONNACK
    return_code: int = 0


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def u8(self) -> int:
        if self.pos >= len(self.data):
            raise DecodeError("short read")
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        if self.pos + 2 > len(self.data):
            raise DecodeError("short read")
        v: int = struct.unpack_from(">H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def blob(self) -> bytes:
        n = self.u16()
        if self.pos + n > len(self.data):
            raise DecodeError("short read")
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v

    def string(self) -> str:
        return self.blob().decode("utf-8", "replace")

    def varint(self) -> int:
        mult, value = 1, 0
        for _ in range(4):
            b = self.u8()
            value += (b & 0x7F) * mult
            if not b & 0x80:
                return value
            mult *= 128
        raise DecodeError("bad varint")

    def skip_properties(self) -> None:
        n = self.varint()
        if self.pos + n > len(self.data):
            raise DecodeError("short properties")
        self.pos += n

    def rest(self) -> bytes:
        return self.data[self.pos :]


def decode_mqtt(data: bytes, protocol_level: int = 4) -> tuple[list[MqttPacket], int]:
    """Decode an MQTT byte stream. Returns packets and the protocol level seen in CONNECT.

    The level matters because MQTT 5 inserts property blocks into most packets; the cloud
    direction never carries CONNECT, so callers pass the level found in the device direction.
    """
    out: list[MqttPacket] = []
    pos = 0
    level = protocol_level
    while pos < len(data):
        start = pos
        b0 = data[pos]
        ptype, flags = b0 >> 4, b0 & 0x0F
        if ptype not in MQTT_TYPES:
            break
        r = _Reader(data[pos + 1 : pos + 5])
        try:
            remaining = r.varint()
        except DecodeError:
            break
        body_start = pos + 1 + r.pos
        if body_start + remaining > len(data):
            break
        body = _Reader(data[body_start : body_start + remaining])
        pos = body_start + remaining
        pk = MqttPacket(type=MQTT_TYPES[ptype], offset=start, flags=flags)
        try:
            if ptype == 1:
                body.string()  # protocol name
                pk.protocol_level = level = body.u8()
                cflags = body.u8()
                pk.clean_start = bool(cflags & 0x02)
                pk.keepalive = body.u16()
                if level == 5:
                    body.skip_properties()
                pk.client_id = body.string()
                if cflags & 0x04:
                    if level == 5:
                        body.skip_properties()
                    body.string()
                    body.blob()
                if cflags & 0x80:
                    pk.username = body.string()
                if cflags & 0x40:
                    pk.password = body.blob()
            elif ptype == 2:
                body.u8()
                pk.return_code = body.u8()
            elif ptype == 3:
                pk.qos = (flags >> 1) & 0x03
                pk.retain = bool(flags & 0x01)
                pk.topic = body.string()
                if pk.qos:
                    pk.packet_id = body.u16()
                if level == 5:
                    body.skip_properties()
                pk.payload = body.rest()
            elif ptype in (4, 5, 6, 7, 9, 11):
                pk.packet_id = body.u16()
            elif ptype in (8, 10):
                pk.packet_id = body.u16()
                if level == 5:
                    body.skip_properties()
                while body.pos < len(body.data):
                    topic = body.string()
                    qos = body.u8() & 0x03 if ptype == 8 else 0
                    pk.subscriptions.append((topic, qos))
        except DecodeError:
            break
        out.append(pk)
    return out, level


def looks_like_mqtt_connect(data: bytes) -> bool:
    return len(data) > 8 and data[0] == 0x10 and (b"MQTT" in data[:12] or b"MQIsdp" in data[:14])


# --------------------------------------------------------------------------- CoAP (RFC 7252)

COAP_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
COAP_METHODS = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE", 5: "FETCH", 6: "PATCH", 7: "iPATCH"}
OPT_URI_HOST, OPT_URI_PATH, OPT_CONTENT_FORMAT, OPT_URI_QUERY = 3, 11, 12, 15


@dataclass
class CoapMessage:
    mtype: str
    code: int
    mid: int
    token: bytes
    options: list[tuple[int, bytes]]
    payload: bytes

    @property
    def code_str(self) -> str:
        return f"{self.code >> 5}.{self.code & 0x1F:02d}"

    @property
    def is_request(self) -> bool:
        return 1 <= self.code <= 31

    @property
    def method(self) -> str:
        return COAP_METHODS.get(self.code, self.code_str)

    @property
    def path(self) -> str:
        segs = [v.decode("utf-8", "replace") for n, v in self.options if n == OPT_URI_PATH]
        return "/" + "/".join(segs)

    @property
    def query(self) -> list[str]:
        return [v.decode("utf-8", "replace") for n, v in self.options if n == OPT_URI_QUERY]

    @property
    def content_format(self) -> int | None:
        for n, v in self.options:
            if n == OPT_CONTENT_FORMAT:
                return int.from_bytes(v, "big") if v else 0
        return None


def _coap_ext(data: bytes, pos: int, v: int) -> tuple[int, int]:
    if v == 13:
        return data[pos] + 13, pos + 1
    if v == 14:
        return struct.unpack_from(">H", data, pos)[0] + 269, pos + 2
    if v == 15:
        raise DecodeError("reserved option nibble")
    return v, pos


def decode_coap(data: bytes) -> CoapMessage:
    if len(data) < 4:
        raise DecodeError("short CoAP message")
    b0 = data[0]
    if b0 >> 6 != 1:
        raise DecodeError("not CoAP version 1")
    tkl = b0 & 0x0F
    if tkl > 8:
        raise DecodeError("bad token length")
    code = data[1]
    mid = struct.unpack_from(">H", data, 2)[0]
    pos = 4
    token = data[pos : pos + tkl]
    pos += tkl
    options: list[tuple[int, bytes]] = []
    number = 0
    try:
        while pos < len(data):
            if data[pos] == 0xFF:
                pos += 1
                break
            delta, length = data[pos] >> 4, data[pos] & 0x0F
            pos += 1
            delta, pos = _coap_ext(data, pos, delta)
            length, pos = _coap_ext(data, pos, length)
            number += delta
            if pos + length > len(data):
                raise DecodeError("truncated option value")
            options.append((number, data[pos : pos + length]))
            pos += length
    except (IndexError, struct.error) as exc:
        raise DecodeError("truncated option") from exc
    return CoapMessage(COAP_TYPES[(b0 >> 4) & 0x03], code, mid, token, options, data[pos:])


def _coap_nib(v: int) -> tuple[int, bytes]:
    if v < 13:
        return v, b""
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack(">H", v - 269)


def encode_coap(msg: CoapMessage) -> bytes:
    types = {v: k for k, v in COAP_TYPES.items()}
    out = bytearray([0x40 | (types[msg.mtype] << 4) | len(msg.token), msg.code])
    out += struct.pack(">H", msg.mid) + msg.token
    last = 0
    for number, value in sorted(msg.options, key=lambda o: o[0]):
        dn, dx = _coap_nib(number - last)
        ln, lx = _coap_nib(len(value))
        last = number
        out.append((dn << 4) | ln)
        out += dx + lx + value
    if msg.payload:
        out += b"\xff" + msg.payload
    return bytes(out)


def looks_like_coap(data: bytes) -> bool:
    try:
        msg = decode_coap(data)
    except (DecodeError, KeyError, IndexError, struct.error):
        return False
    return msg.code == 0 or 1 <= msg.code <= 31 or 64 <= msg.code <= 191


# --------------------------------------------------------------------------- TLS ClientHello


def tls_client_hello_sni(data: bytes) -> str | None:
    """Return the SNI from a TLS ClientHello, or None. Read-only metadata, no decryption."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, version, random
        sid_len = data[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack_from(">H", data, pos)[0]
        pos += 2 + cs_len
        comp_len = data[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            etype, elen = struct.unpack_from(">HH", data, pos)
            pos += 4
            if etype == 0:
                name_len = struct.unpack_from(">H", data, pos + 3)[0]
                return data[pos + 5 : pos + 5 + name_len].decode("ascii", "replace")
            pos += elen
    except (IndexError, struct.error):
        return None
    return None


def looks_like_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] in (0x16, 0x17, 0x15) and data[1] == 0x03
