"""`modigliani install`: fill a shared profile's placeholders from the user's own capture."""

from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import dataclass

from modigliani.capture.model import Capture, Direction
from modigliani.infer.sessions import build_sessions
from modigliani.infer.values import get_path, parse_body
from modigliani.profile.model import Profile


@dataclass
class InstallReport:
    filled: dict[str, str]
    generated: dict[str, str]
    missing: list[str]


def _match_template(template: str, value: str, sep: str = "/") -> dict[str, str] | None:
    a, b = template.split(sep), value.split(sep)
    if len(a) != len(b):
        return None
    out: dict[str, str] = {}
    for t, v in zip(a, b, strict=True):
        if t.startswith("{") and t.endswith("}"):
            out[t[1:-1]] = v
        elif t != v:
            return None
    return out


def _generate(kind: str) -> str:
    if kind in ("token", "key", "secret"):
        return secrets.token_hex(16)
    return uuid.uuid4().hex[:12]


def fill_placeholders(
    profile: Profile,
    captures: list[Capture],
    overrides: dict[str, str] | None = None,
    device: str | None = None,
) -> tuple[Profile, InstallReport]:
    overrides = overrides or {}
    sess = build_sessions(captures, device)
    http_paths = {h.id: h.path for h in profile.handlers.http}
    coap_paths = {h.id: h.path for h in profile.handlers.coap}
    topics = {t.id: t.topic for t in (profile.handlers.mqtt.topics if profile.handlers.mqtt else [])}
    filled: dict[str, str] = {}
    generated: dict[str, str] = {}
    missing: list[str] = []
    out = profile.model_copy(deep=True)
    for name, ph in out.placeholders.items():
        value: str | None = overrides.get(name)
        src = ph.source
        if value is None and src is not None:
            if src.kind == "http_path":
                tmpl = http_paths.get(src.handler or "")
                for ex in sess.http:
                    m = _match_template(tmpl, ex.req.path) if tmpl else None
                    if m and src.selector in m:
                        value = m[src.selector]
                        break
            elif src.kind == "http_body":
                for ex in sess.http:
                    v = get_path(parse_body(ex.req.header("content-type"), ex.req.body), src.selector)
                    if isinstance(v, str):
                        value = v
                        break
            elif src.kind == "http_header":
                value = next((ex.req.header(src.selector) for ex in sess.http if ex.req.header(src.selector)), None)
            elif src.kind == "coap_path":
                tmpl = coap_paths.get(src.handler or "")
                for e in sess.coap:
                    m = _match_template(tmpl, e.msg.path) if tmpl and e.dir is Direction.UP else None
                    if m and src.selector in m:
                        value = m[src.selector]
                        break
            elif src.kind in ("mqtt_client_id", "mqtt_username"):
                for s in sess.mqtt:
                    if s.connect is None:
                        continue
                    text = s.connect.client_id if src.kind == "mqtt_client_id" else (s.connect.username or "")
                    if src.pattern:
                        m2 = re.fullmatch(src.pattern, text)
                        if m2 and m2.groups():
                            value = m2.group(1)
                            break
                    elif text:
                        value = text
                        break
            elif src.kind == "mqtt_topic":
                tmpl = topics.get(src.handler or "")
                for s in sess.mqtt:
                    for me in s.events:
                        m = _match_template(tmpl, me.packet.topic) if tmpl and me.packet.topic else None
                        if m and src.selector in m:
                            value = m[src.selector]
                            break
                    if value:
                        break
        if value is not None:
            ph.value = value
            filled[name] = value
        elif ph.kind in ("token", "key", "secret"):
            ph.value = generated[name] = _generate(ph.kind)
        else:
            missing.append(name)
    out.provenance.scrubbed = False
    return out, InstallReport(filled, generated, missing)
