"""Profile validation: JSON Schema (structure) plus semantic checks (references, templates)."""

from __future__ import annotations

import json
import re
from typing import Any

import jsonschema
from pydantic import ValidationError

from modigliani.profile.model import Profile

TEMPLATE_RE = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
_ROOTS = {"req", "device", "state", "desired", "cmd", "token", "ph", "now", "gen"}
_FIXED = {
    "cmd": {"value", "name", "seq", "id"},
    "token": {"value", "expires_in", "expires_at"},
    "now": {"unix", "unix_ms", "iso"},
    "device": {"key", "vars"},
}


def json_schema() -> dict[str, Any]:
    schema = Profile.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://github.com/ide-bloom/modigliani/docs/profile.schema.json"
    return schema


def schema_errors(data: dict[str, Any]) -> list[str]:
    validator = jsonschema.Draft202012Validator(json_schema())
    errors = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "(root)"
        errors.append(f"{where}: {err.message}")
    return errors


def _templates(obj: Any, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _templates(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _templates(v, f"{path}.{i}")
    elif isinstance(obj, str):
        out += [(path, m.group(1)) for m in TEMPLATE_RE.finditer(obj)]
    return out


def semantic_errors(profile: Profile) -> list[str]:
    errors: list[str] = []
    variables = {v.name for v in profile.state}
    http_ids = {h.id for h in profile.handlers.http}
    topic_ids = {t.id for t in profile.handlers.mqtt.topics} if profile.handlers.mqtt else set()
    coap_ids = {h.id for h in profile.handlers.coap}
    raw_ids = {h.id for h in profile.handlers.raw}
    ws_ids = {h.id for h in profile.handlers.websocket}
    frame_ids = {f.id for f in profile.frames}
    all_ids = [h.id for h in profile.handlers.http] + list(topic_ids) + list(coap_ids) + list(raw_ids) + list(ws_ids)
    if len(all_ids) != len(set(all_ids)):
        errors.append("handler ids must be unique")
    for c in profile.commands:
        if c.variable not in variables:
            errors.append(f"command {c.name}: unknown variable {c.variable}")
        target = {
            "http_poll": http_ids,
            "mqtt": topic_ids,
            "coap_response": coap_ids,
            "raw": raw_ids,
            "websocket": ws_ids,
        }[c.transport]
        if c.handler not in target:
            errors.append(f"command {c.name}: unknown {c.transport} handler {c.handler}")
        if c.transport == "http_poll":
            h = next((h for h in profile.handlers.http if h.id == c.handler), None)
            if h is not None and h.delivers_commands is None:
                errors.append(f"command {c.name}: handler {c.handler} does not deliver commands")
    if profile.auth.token and profile.auth.token.issued_by not in http_ids:
        errors.append(f"auth.token.issued_by: unknown handler {profile.auth.token.issued_by}")
    for ch in profile.handlers.coap:
        if ch.request_frame and ch.request_frame not in frame_ids:
            errors.append(f"coap {ch.id}: unknown frame {ch.request_frame}")
        if ch.response.frame and ch.response.frame.frame not in frame_ids:
            errors.append(f"coap {ch.id}: unknown response frame {ch.response.frame.frame}")
    for rh in profile.handlers.raw:
        for r in rh.rules:
            if r.frame not in frame_ids:
                errors.append(f"raw {rh.id}/{r.id}: unknown frame {r.frame}")
            if r.reply and r.reply.frame not in frame_ids:
                errors.append(f"raw {rh.id}/{r.id}: unknown reply frame {r.reply.frame}")
    if profile.handlers.mqtt:
        for t in profile.handlers.mqtt.topics:
            if t.reply_to and t.reply_to not in topic_ids:
                errors.append(f"mqtt topic {t.id}: reply_to unknown topic {t.reply_to}")
    extracts = [e for h in profile.handlers.http for e in h.extract]
    extracts += [e for t in (profile.handlers.mqtt.topics if profile.handlers.mqtt else []) for e in t.extract]
    extracts += [e for h in profile.handlers.coap for e in h.extract]
    extracts += [e for h in profile.handlers.raw for r in h.rules for e in r.extract]
    extracts += [e for h in profile.handlers.websocket for m in h.messages for e in m.extract]
    for e in extracts:
        if e.variable not in variables:
            errors.append(f"extract {e.source}: unknown variable {e.variable}")
    for ent in profile.home_assistant.entities:
        for ref in (ent.variable, ent.current_temperature, ent.target_temperature, ent.hvac_mode, ent.hvac_action):
            if ref is not None and ref not in variables:
                errors.append(f"home_assistant entity {ent.key}: unknown variable {ref}")
    data = profile.model_dump(mode="json")
    for path, expr in _templates({k: data[k] for k in ("handlers", "commands", "dns")}):
        parts = expr.split(".")
        root = parts[0]
        if root not in _ROOTS:
            errors.append(f"{path}: unknown template root in {{{{{expr}}}}}")
        elif root in ("state", "desired") and (len(parts) < 2 or parts[1] not in variables):
            errors.append(f"{path}: unknown variable in {{{{{expr}}}}}")
        elif root == "ph" and (len(parts) < 2 or parts[1] not in profile.placeholders):
            errors.append(f"{path}: unknown placeholder in {{{{{expr}}}}}")
        elif root in _FIXED and (len(parts) < 2 or parts[1] not in _FIXED[root]):
            errors.append(f"{path}: unknown field in {{{{{expr}}}}}")
    return errors


def validate(data: dict[str, Any]) -> tuple[Profile | None, list[str]]:
    errors = schema_errors(data)
    if errors:
        return None, errors
    try:
        profile = Profile.model_validate(data)
    except ValidationError as exc:
        return None, [json.dumps(e["loc"]) + ": " + e["msg"] for e in exc.errors()]
    return profile, semantic_errors(profile)
