"""Profile schema validation, I/O, scrubbing, signatures and install."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from modigliani.annotate.model import parse_label
from modigliani.infer.engine import infer_profile
from modigliani.profile import sign
from modigliani.profile.install import fill_placeholders
from modigliani.profile.io import dump_profile, load_profile, save_profile
from modigliani.profile.model import Profile
from modigliani.profile.scrub import scrub
from modigliani.profile.validate import json_schema, schema_errors, semantic_errors, validate
from tests.unit.builders import capture
from tests.unit.test_engine import _plug_capture

REPO = Path(__file__).resolve().parents[2]


def _profile() -> Profile:
    f, anns = _plug_capture()
    return infer_profile(
        [capture(f.flow, name="alice-home")], [parse_label("turned on", anns[0] - 0.5)], device="dev"
    ).profile


def test_valid_profile_passes_schema_and_semantics(tmp_path: Path) -> None:
    p = _profile()
    data = p.model_dump(mode="json")
    parsed, errors = validate(data)
    assert parsed is not None and errors == []
    for suffix in (".yaml", ".json"):
        path = tmp_path / f"p{suffix}"
        save_profile(p, path)
        assert load_profile(path) == p


def test_schema_rejects_bad_profiles() -> None:
    data = _profile().model_dump(mode="json")
    data["schema_version"] = 2
    data["handlers"]["http"][0]["method"] = 7
    data["surprise"] = True
    errors = schema_errors(data)
    assert any("schema_version" in e for e in errors)
    assert any("surprise" in e for e in errors)
    _, errors2 = validate(data)
    assert errors2


def test_semantic_errors_catch_dangling_references() -> None:
    p = _profile()
    p.commands[0].variable = "nope"
    p.handlers.http[0].response.body = {"x": "{{state.missing}}", "y": "{{bogus.thing}}", "z": "{{ph.unknown}}"}
    errors = semantic_errors(p)
    assert any("unknown variable nope" in e for e in errors)
    assert any("state.missing" in e for e in errors)
    assert any("bogus.thing" in e for e in errors)
    assert any("ph.unknown" in e for e in errors)


def test_docs_schema_is_in_sync() -> None:
    documented = json.loads((REPO / "docs" / "profile.schema.json").read_text(encoding="utf-8"))
    assert documented == json_schema(), "run: uv run python scripts/gen_schema.py"


def test_scrub_removes_every_identifier() -> None:
    p = _profile()
    # Plant identifiers of every kind the scrubber must catch.
    handler = p.handlers.http[0]
    handler.response.body = {
        "token": "{{token.value}}",
        "owner": "alice@example.com",
        "mac": "AA:BB:CC:DD:EE:FF",
        "ssid": "AliceHome",
        "home": "203.0.113.77",
        "apikey": "9f86d081884c7d659a2feaa0c55ad015",
        "device_uuid": "123e4567-e89b-12d3-a456-426614174000",
        "imei": "356938035643809",
        "lat": 52.1234,
    }
    p.device.fingerprints[0].pattern = "^AB\\-998877\\.vendor\\.example$"
    p.name = "AB-998877"
    secrets = [
        "AB-998877",
        "alice@example.com",
        "AA:BB:CC:DD:EE:FF",
        "aabbccddeeff",
        "AliceHome",
        "203.0.113.77",
        "9f86d081884c7d659a2feaa0c55ad015",
        "123e4567-e89b-12d3-a456-426614174000",
        "356938035643809",
        "alice-home",
        "52.1234",
        "AB\\-998877",
    ]
    scrubbed, changes = scrub(p)
    text = dump_profile(scrubbed) + dump_profile(scrubbed, "json")
    for s in secrets:
        assert s.lower() not in text.lower(), s
    assert scrubbed.provenance.scrubbed
    assert all(ph.value is None for ph in scrubbed.placeholders.values())
    assert scrubbed.provenance.captures[0].name == "capture-1"
    body = scrubbed.handlers.http[0].response.body
    assert isinstance(body, dict) and re.fullmatch(r"\{\{ph\.account_\d\}\}", str(body["owner"]))
    assert body["token"] == "{{token.value}}"
    # Structure is untouched: entity keys, handler ids and template expressions survive.
    assert [e.key for e in scrubbed.home_assistant.entities] == [e.key for e in p.home_assistant.entities]
    assert semantic_errors(scrubbed) == []
    assert any(c.reason == "placeholder value" for c in changes)


def test_install_refills_placeholders() -> None:
    f, _anns = _plug_capture()
    cap = capture(f.flow)
    scrubbed, _ = scrub(infer_profile([cap], [], device="dev").profile)
    filled, report = fill_placeholders(scrubbed, [cap])
    assert report.filled.get("serial") == "AB-998877"
    assert filled.placeholders["serial"].value == "AB-998877"
    assert not report.missing


def test_signatures(tmp_path: Path) -> None:
    key = tmp_path / "k.pem"
    sign.generate_key(key)
    with pytest.raises(FileExistsError):
        sign.generate_key(key)
    path = tmp_path / "p.yaml"
    save_profile(_profile(), path)
    assert sign.verify_file(path).status == "unsigned"
    sign.sign_file(path, sign.load_key(key))
    pub = json.loads(sign.sig_path(path).read_text())["public_key"]
    assert sign.verify_file(path).status == "valid"
    assert sign.verify_file(path, trusted=[pub]).status == "valid"
    assert sign.verify_file(path, trusted=["other"]).status == "untrusted"
    path.write_text(path.read_text() + "# tampered\n")
    assert sign.verify_file(path).status == "invalid"


def test_library_profiles_validate_and_are_signed() -> None:
    library = REPO / "profiles" / "library"
    files = sorted(library.glob("*.yaml"))
    # The published maintainer key (server config example) must be the one that signed them.
    config = yaml.safe_load((REPO / "server" / "config.example.yaml").read_text(encoding="utf-8"))
    trusted = config["trusted_keys"]
    assert {f.stem for f in files} >= {"test-smartplug", "test-thermostat", "test-sensor"}
    for f in files:
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        parsed, errors = validate(data)
        assert parsed is not None and errors == [], (f, errors)
        assert parsed.provenance.scrubbed and parsed.provenance.license in ("CC0-1.0", "CC-BY-4.0")
        assert sign.verify_file(f, trusted=trusted).status == "valid", f
