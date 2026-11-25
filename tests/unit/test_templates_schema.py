"""Path-template and topic-variable inference, response templatization, schema inference."""

from __future__ import annotations

from modigliani.infer.schema import infer_schema
from modigliani.infer.templates import TemplContext, infer_templates, pattern_from_value, templatize
from modigliani.infer.values import is_identifier, time_kind, token_format


def test_identifier_heuristics() -> None:
    for seg in ("SP-1A2B3C", "12345", "0f1e2d3c4b5a", "aa:bb:cc:dd:ee:ff", "123e4567-e89b-12d3-a456-426614174000"):
        assert is_identifier(seg), seg
    for seg in ("v1", "v2.1", "status", "commands", "api", "0", "1"):
        assert not is_identifier(seg), seg


def test_path_templates_name_parameters() -> None:
    paths = [
        "/api/v1/devices/SP-1A2B3C/status",
        "/api/v1/devices/SP-1A2B3C/commands",
        "/api/v1/time",
        "/api/v1/users/99812/home",
    ]
    tm = infer_templates(paths, "/", known={"serial": "SP-1A2B3C"})
    assert tm["/api/v1/devices/SP-1A2B3C/status"].template == "/api/v1/devices/{serial}/status"
    assert tm["/api/v1/devices/SP-1A2B3C/status"].params == {"serial": "SP-1A2B3C"}
    assert tm["/api/v1/time"].template == "/api/v1/time"
    assert tm["/api/v1/users/99812/home"].template == "/api/v1/users/{user_id}/home"


def test_plain_words_never_become_parameters() -> None:
    tm = infer_templates(["/a/status", "/a/commands", "/a/time/now/x", "/a/b/now/x"], "/")
    assert {m.template for m in tm.values()} == {"/a/status", "/a/commands", "/a/time/now/x", "/a/b/now/x"}


def test_topic_variables() -> None:
    topics = ["thermo/TH-9F8E7D/telemetry", "thermo/TH-9F8E7D/cmd", "thermo/TH-9F8E7D/time/req"]
    tm = infer_templates(topics, "/", known={"device_id": "TH-9F8E7D"})
    assert tm["thermo/TH-9F8E7D/cmd"].template == "thermo/{device_id}/cmd"
    assert pattern_from_value("thermo-TH-9F8E7D", {"device_id": "TH-9F8E7D"}) == "thermo-{device_id}"


def test_templatize_rules() -> None:
    ts = 1_800_000_000.0
    ctx = TemplContext(
        ts=ts,
        path_params={"serial": "SP-1A2B3C"},
        query={"current": "1.4.2"},
        body={"name": "kitchen"},
        token="ab" * 16,
        token_lifetime=3600,
        siblings={"seq": [1, 2, 3], "id": ["0" * 31 + "a", "0" * 31 + "b", "0" * 31 + "c"]},
    )
    body = {
        "token": "ab" * 16,
        "expires_in": 3600,
        "device": "SP-1A2B3C",
        "latest": "1.4.2",
        "room": "kitchen",
        "epoch": int(ts),
        "ms": int(ts * 1000),
        "iso": "2027-01-15T08:00:00Z",
        "seq": 1,
        "id": "0" * 31 + "a",
        "ok": True,
    }
    out = templatize(body, ctx)
    assert out["token"] == "{{token.value}}"
    assert out["expires_in"] == "{{token.expires_in}}"
    assert out["device"] == "{{req.path.serial}}"
    assert out["latest"] == "{{req.query.current}}"
    assert out["room"] == "{{req.body.name}}"
    assert out["epoch"] == "{{now.unix}}" and out["ms"] == "{{now.unix_ms}}" and out["iso"] == "{{now.iso}}"
    assert out["seq"] == "{{gen.seq}}"
    assert out["id"] == "{{gen.hex.32}}"
    assert out["ok"] is True


def test_value_shapes() -> None:
    assert token_format("123e4567-e89b-12d3-a456-426614174000") == "uuid"
    assert token_format("deadbeef" * 4) == "hex"
    assert token_format("short") is None
    assert time_kind(1_800_000_000, 1_800_000_100) == "unix"
    assert time_kind(True, 1_800_000_000) is None


def test_schema_inference_merges_samples() -> None:
    schema = infer_schema([{"power": True, "watts": 1.5}, {"power": False, "watts": 0, "extra": "x"}, None])
    assert schema is not None
    assert schema["type"] == "object"
    assert schema["properties"]["power"]["type"] == "boolean"
    assert set(schema["required"]) == {"power", "watts"}
    assert "$schema" not in schema
    assert infer_schema([None]) is None
