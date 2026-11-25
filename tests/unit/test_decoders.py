"""HTTP, WebSocket, MQTT, CoAP and TLS ClientHello decoding."""

from __future__ import annotations

import gzip
import ssl

import pytest

from modigliani.infer import decoders as d
from tests.unit.builders import http_request, http_response, mqtt_connect, mqtt_publish, mqtt_subscribe


def test_http_keepalive_requests_and_bodies() -> None:
    stream = http_request("POST", "/a?x=1", {"k": 1}) + http_request("GET", "/b")
    reqs = d.decode_http_requests(stream)
    assert [(r.method, r.path) for r in reqs] == [("POST", "/a"), ("GET", "/b")]
    assert reqs[0].query == {"x": ["1"]}
    assert reqs[0].body == b'{"k": 1}'
    assert reqs[0].header("content-type") == "application/json"


def test_http_responses_chunked_and_gzip() -> None:
    raw = gzip.compress(b'{"ok": true}')
    gz = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + str(len(raw)).encode() + b"\r\n\r\n" + raw
    stream = http_response(200, {"a": 1}, chunked=True) + gz + b"HTTP/1.1 204 No Content\r\n\r\n"
    resps = d.decode_http_responses(stream, ["GET", "GET", "DELETE"])
    assert [r.status for r in resps] == [200, 200, 204]
    assert resps[0].body == b'{"a": 1}'
    assert resps[1].body == b'{"ok": true}'


def test_http_truncated_stream_stops_cleanly() -> None:
    stream = http_request("POST", "/a", {"k": 1})
    assert d.decode_http_requests(stream[:-3]) == []


def test_websocket_frames_masked_and_fragmented() -> None:
    a = d.encode_ws_frame(1, b"hello", mask=b"\x01\x02\x03\x04")
    first = bytes([0x01, 0x03]) + b"abc"  # text, not FIN
    cont = bytes([0x80, 0x03]) + b"def"  # continuation, FIN
    big = d.encode_ws_frame(2, b"x" * 300)
    msgs = d.decode_ws_frames(a + first + cont + big)
    assert [(m.opcode, m.payload) for m in msgs] == [(1, b"hello"), (1, b"abcdef"), (2, b"x" * 300)]


def test_mqtt_311_session() -> None:
    stream = (
        mqtt_connect("dev-1", "user", "pw", keepalive=20)
        + mqtt_subscribe("a/+/cmd")
        + mqtt_publish("a/1/t", b'{"v":1}', qos=1, pid=7)
    )
    pkts, level = d.decode_mqtt(stream)
    assert level == 4
    connect, sub, pub = pkts
    assert (connect.client_id, connect.username, connect.password, connect.keepalive) == ("dev-1", "user", b"pw", 20)
    assert sub.subscriptions == [("a/+/cmd", 1)]
    assert (pub.topic, pub.payload, pub.qos, pub.packet_id) == ("a/1/t", b'{"v":1}', 1, 7)


def test_mqtt_5_properties_are_skipped() -> None:
    stream = mqtt_connect("dev-5", level=5) + mqtt_publish("x/y", b"hi", level=5, retain=True)
    pkts, level = d.decode_mqtt(stream)
    assert level == 5
    assert pkts[1].topic == "x/y" and pkts[1].payload == b"hi" and pkts[1].retain
    assert d.looks_like_mqtt_connect(stream)


def test_coap_roundtrip() -> None:
    msg = d.CoapMessage(
        "CON",
        2,
        0x1234,
        b"\xaa\xbb",
        [(d.OPT_URI_PATH, b"s"), (d.OPT_URI_PATH, b"SN1"), (d.OPT_CONTENT_FORMAT, b"\x2a"), (d.OPT_URI_QUERY, b"q=1")],
        b"\x01\x02",
    )
    raw = d.encode_coap(msg)
    back = d.decode_coap(raw)
    assert (back.mtype, back.method, back.mid, back.token) == ("CON", "POST", 0x1234, b"\xaa\xbb")
    assert back.path == "/s/SN1" and back.query == ["q=1"] and back.content_format == 42
    assert back.payload == b"\x01\x02" and back.is_request
    assert d.looks_like_coap(raw)
    ack = d.decode_coap(d.encode_coap(d.CoapMessage("ACK", 0x44, 1, b"", [], b"")))
    assert ack.code_str == "2.04" and not ack.is_request


def test_coap_rejects_garbage() -> None:
    with pytest.raises(d.DecodeError):
        d.decode_coap(b"\x00\x01")
    assert not d.looks_like_coap(b"\xff\xff\xff\xff\xff")


def test_tls_client_hello_sni() -> None:
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname="api.vendor.example")
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    hello = outgoing.read()
    assert d.looks_like_tls(hello)
    assert d.tls_client_hello_sni(hello) == "api.vendor.example"
    assert d.tls_client_hello_sni(b"GET / HTTP/1.1\r\n") is None
