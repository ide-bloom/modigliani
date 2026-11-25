"""Whole-engine inference on synthetic captures: HTTP polling, MQTT, raw TCP and TLS verdicts."""

from __future__ import annotations

import json
import struct

from modigliani.annotate.model import parse_label
from modigliani.capture.model import Direction, Segment, TlsOutcome
from modigliani.infer import frames as fr
from modigliani.infer.engine import infer_profile
from modigliani.profile.validate import semantic_errors
from tests.unit.builders import (
    FlowBuilder,
    capture,
    http_request,
    http_response,
    mqtt_connect,
    mqtt_publish,
    mqtt_subscribe,
)

T0 = 1_800_000_000.0
TOKEN = "f00dfeedcafebabe" * 2


def _plug_capture() -> tuple[FlowBuilder, list[float]]:
    f = FlowBuilder(0)
    f.up(T0, http_request("POST", "/v1/login", {"serial": "AB-998877", "key": "x"}))
    f.down(T0 + 0.1, http_response(200, {"token": TOKEN, "ttl": 900}))
    power, seq, t = False, 0, T0 + 1
    actions = {T0 + 5: True, T0 + 12: False}
    anns = []
    while t < T0 + 20:
        cmds = []
        for at, value in list(actions.items()):
            if t >= at:
                seq += 1
                cmds.append({"id": seq, "cmd": "relay", "on": value})
                power = value
                anns.append(at)
                del actions[at]
        auth = {"Authorization": f"Bearer {TOKEN}"}
        f.up(t, http_request("GET", "/v1/dev/AB-998877/poll", headers=auth)).down(
            t + 0.05, http_response(200, {"queue": cmds})
        )
        f.up(
            t + 0.2, http_request("POST", "/v1/dev/AB-998877/report", {"on": power, "w": 30.5 if power else 0.0}, auth)
        )
        f.down(t + 0.25, http_response(200, {"ok": True}))
        t += 1.0
    return f, anns


def test_http_polling_device() -> None:
    f, anns = _plug_capture()
    annotations = [parse_label("turned on", anns[0] - 0.5), parse_label("turned off", anns[1] - 0.5)]
    result = infer_profile([capture(f.flow)], annotations, device="dev", profile_id="plug")
    p = result.profile
    assert result.revivable and p.revivability.status == "revivable"
    assert {v.name: v.writable for v in p.state} == {"power": True, "w": False}
    cmd = p.commands[0]
    assert cmd.transport == "http_poll" and cmd.template == {"id": "{{gen.seq}}", "cmd": "relay", "on": "{{cmd.value}}"}
    poll = next(h for h in p.handlers.http if h.id == cmd.handler)
    assert poll.path == "/v1/dev/{serial}/poll" and poll.auth == "token" and poll.response.body == {"queue": []}
    assert poll.delivers_commands is not None and poll.delivers_commands.path == "queue"
    assert p.auth.token is not None and p.auth.token.lifetime_s == 900 and p.auth.token.issued_by == "post_login"
    assert p.placeholders["serial"].value == "AB-998877"
    assert all(h.evidence for h in p.handlers.http)
    assert semantic_errors(p) == []
    assert {e.platform for e in p.home_assistant.entities} == {"switch", "sensor"}


def test_mqtt_device_with_request_response() -> None:
    f = FlowBuilder(0, port=8883, hostname="broker.vendor.example")
    f.up(T0, mqtt_connect("acme-XY-123456", "XY-123456", "pw") + mqtt_subscribe("dev/XY-123456/set"))
    for i in range(12):
        t = T0 + 1 + i
        mode = "eco" if i >= 6 else "comfort"
        f.up(t, mqtt_publish("dev/XY-123456/state", json.dumps({"mode": mode, "t": 20 + i % 3}).encode()))
        if i % 4 == 0:
            f.up(t + 0.1, mqtt_publish("dev/XY-123456/clock/get", b"{}"))
            f.down(t + 0.2, mqtt_publish("dev/XY-123456/clock", json.dumps({"now": int(t)}).encode()))
    f.down(T0 + 6.5, mqtt_publish("dev/XY-123456/set", b'{"mode": "eco"}', qos=1))
    result = infer_profile([capture(f.flow)], [parse_label("mode eco", T0 + 6.3)], device="dev")
    p = result.profile
    assert p.handlers.mqtt is not None and p.handlers.mqtt.identity_var == "device_id"
    clock = next(t for t in p.handlers.mqtt.topics if t.topic == "dev/{device_id}/clock")
    assert clock.reply_to is not None and clock.housekeeping == "time_sync" and clock.payload == {"now": "{{now.unix}}"}
    assert p.auth.mqtt is not None and p.auth.mqtt.client_id_pattern == "acme-{device_id}"
    assert [c.name for c in p.commands] == ["set_mode"]
    assert p.tls.mode == "local_ca"


def test_raw_tcp_device_framing_and_rules() -> None:
    def frame(t: int, body: bytes) -> bytes:
        core = bytes([t]) + body
        out = struct.pack(">H", len(core) + 2) + core
        return out + bytes([fr.xor8(out)])

    f = FlowBuilder(0, port=9000, hostname="raw.vendor.example", tls=TlsOutcome.PLAINTEXT)
    for i, reading in enumerate((20, 22, 21, 23, 22, 24)):
        t = T0 + i
        f.up(t, frame(0x10, bytes([reading, 50])))
        f.down(t + 0.1, frame(0x11, b"\x00"))
    result = infer_profile([capture(f.flow)], [], device="dev")
    raw = result.profile.handlers.raw[0]
    assert raw.transport == "tcp" and raw.port == 9000
    assert raw.framing.kind == "length_prefixed"
    assert raw.rules and raw.rules[0].reply is not None
    layout = result.profile.frame(raw.rules[0].frame)
    assert layout is not None and layout.checksum is not None and layout.checksum.algorithm == "xor8"
    assert [v.name for v in result.profile.state] == ["field_3"]


def test_strict_tls_device_is_not_revivable() -> None:
    f = FlowBuilder(0, hostname="secure.vendor.example", tls=TlsOutcome.REJECTED_LOCAL_CA)
    f.flow.metadata_only = True
    f.flow.segments.append(Segment.metadata(T0, Direction.UP, 0))
    g = FlowBuilder(1, hostname="secure.vendor.example", tls=TlsOutcome.PASSTHROUGH)
    g.flow.metadata_only = True
    g.flow.segments += [Segment.metadata(T0 + 1, Direction.UP, 517), Segment.metadata(T0 + 1.1, Direction.DOWN, 3000)]
    result = infer_profile([capture(f.flow, g.flow)], [], device="dev")
    assert not result.revivable
    assert result.profile.tls.mode == "strict_verification"
    assert "firmware access" in result.profile.revivability.reasons[0]
    assert {h.tls_outcome for h in result.profile.revivability.hosts} == {"rejected_local_ca", "passthrough"}


def test_passive_tls_is_untested() -> None:
    f = FlowBuilder(0, tls=TlsOutcome.UNTESTED)
    f.flow.metadata_only = True
    f.flow.segments.append(Segment.metadata(T0, Direction.UP, 300))
    result = infer_profile([capture(f.flow)], [], device="dev")
    assert result.profile.revivability.status == "partial"
    assert "--mode proxy" in result.profile.revivability.reasons[0]
