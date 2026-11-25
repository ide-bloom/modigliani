"""Auth-flow detection and state/annotation correlation."""

from __future__ import annotations

import base64
import json

from modigliani.annotate.model import Annotation, AnnotationKind
from modigliani.capture.model import Direction
from modigliani.infer.auth import detect_token_auth
from modigliani.infer.sessions import Ref, build_sessions
from modigliani.infer.state import FieldSeries, Obs, correlate, is_counter_or_time, match_value
from tests.unit.builders import FlowBuilder, capture, http_request, http_response

TOKEN = "0123456789abcdef" * 2


def _login_flow(location: str) -> FlowBuilder:
    f = FlowBuilder(0)
    f.up(1.0, http_request("POST", "/auth", {"serial": "SN-12345", "secret": "pw"}))
    f.down(1.1, http_response(200, {"session": {"token": TOKEN, "expires_in": 600}}))
    if location == "bearer":
        req = http_request("GET", "/data", headers={"Authorization": f"Bearer {TOKEN}"})
    elif location == "header":
        req = http_request("GET", "/data", headers={"X-Session": TOKEN})
    else:
        req = http_request("GET", f"/data?tok={TOKEN}")
    f.up(2.0, req).down(2.1, http_response(200, {}))
    return f


def test_token_detected_in_each_location() -> None:
    for location, expected in (
        ("bearer", ("bearer", "Authorization")),
        ("header", ("header", "X-Session")),
        ("query", ("query", "tok")),
    ):
        sess = build_sessions([capture(_login_flow(location).flow)])
        found = detect_token_auth(sess.http)
        assert found is not None, location
        assert (found.location, found.name) == expected
        assert found.format == "hex" and found.length == 32 and found.lifetime_s == 600
        assert sess.http[found.issuer_index].req.path == "/auth"


def test_jwt_lifetime_and_no_token() -> None:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    jwt = enc({"alg": "HS256"}) + "." + enc({"iat": 100, "exp": 1900}) + "." + "c2lnbmF0dXJlLXNpZ25hdHVyZQ"
    f = FlowBuilder(0).up(1, http_request("POST", "/login", {"u": "x"})).down(1.1, http_response(200, {"jwt": jwt}))
    f.up(2, http_request("GET", "/x", headers={"Authorization": f"Bearer {jwt}"})).down(2.1, http_response(200, {}))
    found = detect_token_auth(build_sessions([capture(f.flow)]).http)
    assert found is not None and found.format == "jwt" and found.lifetime_s == 1800
    plain = FlowBuilder(0).up(1, http_request("GET", "/a")).down(1.1, http_response(200, {"x": 1}))
    assert detect_token_auth(build_sessions([capture(plain.flow)]).http) is None


def test_match_value_encodings() -> None:
    assert match_value(True, True) is not None
    m = match_value("ON", True)
    assert m is not None and m.value_map == {'"on"': True, '"off"': False}
    assert match_value(1, True) is not None and match_value(0, True) is None
    m2 = match_value(225, 22.5)
    assert m2 is not None and m2.scale == 0.1
    assert match_value("Cool", "cool") is not None
    assert match_value(None, 1) is None


def _series(
    channel: str, path: str, direction: Direction, values: list[tuple[float, object]], name: str | None = None
) -> FieldSeries:
    return FieldSeries(
        channel, path, direction, [Obs(t, v, Ref("c", 0, i)) for i, (t, v) in enumerate(values)], name=name
    )  # type: ignore[arg-type]


def test_correlation_finds_command_and_report() -> None:
    telemetry = _series(
        "mqtt:telemetry", "payload.setpoint", Direction.UP, [(t, 20.0 if t < 12 else 22.5) for t in range(30)]
    )
    temp = _series("mqtt:telemetry", "payload.temp", Direction.UP, [(t, 20.0 + t / 10) for t in range(30)])
    cmd = _series("mqtt:cmd", "payload.setpoint", Direction.DOWN, [(10.5, 22.5)])
    uptime = _series("mqtt:telemetry", "payload.uptime", Direction.UP, [(t, t * 3) for t in range(30)])
    variables = correlate(
        [telemetry, temp, cmd, uptime],
        [Annotation(ts=10.0, label="set 22.5 C", value=22.5, unit="°C")],
        ref_ts=1_800_000_000.0,
    )
    by = {v.name: v for v in variables}
    assert by["setpoint"].writable and by["setpoint"].command is cmd and by["setpoint"].report is telemetry
    assert not by["temp"].writable and by["temp"].confidence == "variation"
    assert "uptime" not in by  # counters never become state


def test_name_rule_without_annotations() -> None:
    up = _series("mqtt:t", "payload.mode", Direction.UP, [(1, "heat"), (5, "cool")])
    down = _series("mqtt:c", "payload.mode", Direction.DOWN, [(4, "cool")])
    v = correlate([up, down], [], ref_ts=1_800_000_000.0)
    assert v[0].name == "mode" and v[0].writable and v[0].confidence == "name"


def test_boolean_actions_need_two_state_fields() -> None:
    seq = _series("http:cmds:resp", "body.commands.0.seq", Direction.DOWN, [(10.2, 1), (20.2, 2)])
    power = _series("http:cmds:resp", "body.commands.0.power", Direction.DOWN, [(10.2, True), (20.2, False)])
    anns = [Annotation(ts=10.0, label="turned on", value=True), Annotation(ts=20.0, label="turned off", value=False)]
    variables = correlate([seq, power], anns, ref_ts=1_800_000_000.0)
    assert [(v.name, v.command is power) for v in variables] == [("power", True)]


def test_reading_annotation_marks_sensor() -> None:
    hum = _series("coap:t:req", "fields.field_5", Direction.UP, [(t, 40 + (t % 3)) for t in range(20)], name="field_5")
    ann = Annotation(
        ts=10.5, label="app shows humidity 41 %", kind=AnnotationKind.READING, variable="humidity", value=41, unit="%"
    )
    v = correlate([hum], [ann], ref_ts=1_800_000_000.0)
    assert v[0].name == "humidity" and not v[0].writable and v[0].unit == "%"


def test_counter_detection() -> None:
    assert is_counter_or_time(_series("x", "payload.ts", Direction.UP, [(1, 1_700_000_000)]), 1_700_000_000)
    assert not is_counter_or_time(_series("x", "payload.t", Direction.UP, [(1, 3), (2, 1), (3, 2)]), 1_800_000_000.0)
