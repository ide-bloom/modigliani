"""Scrubbing: remove every per-user identifier before a profile is shared.

Serial numbers, device IDs, account data, tokens, keys, network names and addresses become
`{{ph.NAME}}` placeholders whose values are filled from the installer's own capture
(`modigliani install`). Detection combines three sources:
1. placeholders inference already knows (identity values, MQTT client IDs);
2. values under sensitive key names (serial, mac, ssid, password, token, email, ...);
3. shape detectors (MAC, e-mail, IPv4, UUID, token-shaped strings, long digit runs).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, cast

from modigliani.infer.values import token_format
from modigliani.profile.model import Placeholder, Profile

_SENSITIVE_KEYS = {
    "serial",
    "sn",
    "serial_number",
    "serialnumber",
    "mac",
    "mac_address",
    "macaddress",
    "ssid",
    "wifi",
    "password",
    "passwd",
    "pass",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "private_key",
    "email",
    "e_mail",
    "account",
    "user",
    "username",
    "user_id",
    "userid",
    "owner",
    "device_id",
    "deviceid",
    "did",
    "uuid",
    "imei",
    "lat",
    "lon",
    "latitude",
    "longitude",
    "home_id",
    "location",
    "address",
    "phone",
    "nickname",
    "alias",
    "room",
    "home",
    "home_name",
    "device_name",
}
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_DIGITS = re.compile(r"\b\d{8,}\b")
_TEMPLATE = re.compile(r"\{\{[^{}]*\}\}")
# Paths never scrubbed: they hold structure, not data.
_SKIP_KEYS = {
    "schema_version",
    "type",
    "kind",
    "method",
    "transport",
    "platform",
    "algorithm",
    "format",
    "location",
    "direction",
    "payload_type",
    "body_type",
    "mode",
    "status",
    "tls_outcome",
    "generated_by",
    "license",
    "created",
    "id",
    "handler",
    "issued_by",
    "variable",
    "frame",
    "key",
    "name",
    "unit",
    "device_class",
    "state_class",
    "source",
    "code",
    "endian",
}
# Keys whose values are vendor message data (where vendor field names are meaningful).
_DATA_KEYS = {"body", "payload", "template", "reply", "match", "values", "request_schema", "payload_schema"}


@dataclass
class ScrubChange:
    path: str
    before: str
    after: str
    reason: str


def _variants(value: str) -> list[str]:
    out = {value}
    if _MAC.fullmatch(value):
        hexd = re.sub(r"[^0-9a-fA-F]", "", value)
        for sep in (":", "-", ""):
            out.add(sep.join(hexd[i : i + 2] for i in range(0, 12, 2)))
    return sorted(out, key=len, reverse=True)


def _kind_for(value: str, key: str) -> str:
    low = key.lower()
    if _MAC.fullmatch(value) or "mac" in low:
        return "mac"
    if _EMAIL.fullmatch(value) or low in ("email", "account", "user", "username", "owner"):
        return "account"
    if "ssid" in low or "wifi" in low:
        return "ssid"
    if low in ("password", "passwd", "pass", "secret"):
        return "secret"
    if low in ("api_key", "apikey", "key", "private_key"):
        return "key"
    if "token" in low or token_format(value):
        return "token"
    if _IPV4.fullmatch(value):
        return "ip"
    if "serial" in low or low == "sn":
        return "serial"
    return "device_id"


def _public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


class _Scrubber:
    def __init__(self, profile: Profile) -> None:
        self.profile = profile
        self.values: dict[str, str] = {}  # sensitive literal -> placeholder name
        self.placeholders: dict[str, Placeholder] = {}
        self.changes: list[ScrubChange] = []
        for name, ph in profile.placeholders.items():
            self.placeholders[name] = ph.model_copy(update={"value": None})
            if isinstance(ph.value, str) and ph.value:
                for v in _variants(ph.value):
                    self.values[v] = name
                self.changes.append(
                    ScrubChange(f"placeholders.{name}.value", ph.value, "(removed)", "placeholder value")
                )

    def register(self, value: str, key: str) -> str:
        if value in self.values:
            return self.values[value]
        kind = _kind_for(value, key)
        n = 1
        while f"{kind}_{n}" in self.placeholders:
            n += 1
        name = f"{kind}_{n}"
        self.placeholders[name] = Placeholder(kind=cast(Any, kind), description=f"Scrubbed {kind} found under '{key}'")
        for v in _variants(value):
            self.values[v] = name
        return name

    def detect(self, obj: Any, key: str = "", in_data: bool = False) -> None:
        """First pass: learn sensitive values so that every occurrence is replaced consistently.

        Key-name rules apply only inside message data (bodies, payloads, templates), where keys
        are the vendor's field names; elsewhere keys are profile structure (e.g. an entity `key`).
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                if not in_data and k in ("placeholders", "provenance"):
                    continue
                self.detect(v, str(k), in_data or k in _DATA_KEYS)
        elif isinstance(obj, list):
            for v in obj:
                self.detect(v, key, in_data)
        elif isinstance(obj, str) and (in_data or key not in _SKIP_KEYS):
            text = _TEMPLATE.sub("", obj)
            norm = key.lower().replace("-", "_")
            if in_data and norm in _SENSITIVE_KEYS and text.strip() and len(text) >= 2:
                self.register(text, key)
            for rx in (_MAC, _EMAIL, _UUID, _DIGITS):
                for m in rx.finditer(text):
                    self.register(m.group(0), key)
            for m in _IPV4.finditer(text):
                if not m.group(0).startswith(("0.", "127.")):
                    self.register(m.group(0), key)
            for word in re.split(r"[\s\"'/=&?,;:]+", text):
                if token_format(word):
                    self.register(word, key)
        elif isinstance(obj, int | float) and not isinstance(obj, bool):
            if in_data and key.lower() in ("lat", "lon", "latitude", "longitude"):
                self.register(str(obj), key)

    def rewrite(self, obj: Any, path: str, key: str = "", in_data: bool = False) -> Any:
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                sub = f"{path}.{k}" if path else str(k)
                if path == "" and k in ("placeholders", "provenance"):
                    out[k] = v
                    continue
                out[k] = self.rewrite(v, sub, str(k), in_data or k in _DATA_KEYS)
            return out
        if isinstance(obj, list):
            return [self.rewrite(v, f"{path}.{i}", key, in_data) for i, v in enumerate(obj)]
        if isinstance(obj, str) and (in_data or key not in _SKIP_KEYS or key == "name"):
            new = obj
            is_pattern = key == "pattern"
            for value, name in sorted(self.values.items(), key=lambda kv: -len(kv[0])):
                if is_pattern:
                    new = re.sub(re.escape(re.escape(value)), ".+", new, flags=re.IGNORECASE)
                    new = re.sub(re.escape(value), ".+", new, flags=re.IGNORECASE)
                else:
                    new = re.sub(re.escape(value), "{{ph." + name + "}}", new, flags=re.IGNORECASE)
            if new != obj:
                self.changes.append(ScrubChange(path, obj, new, "identifier"))
            return new
        if isinstance(obj, int | float) and not isinstance(obj, bool) and str(obj) in self.values:
            name = self.values[str(obj)]
            self.changes.append(ScrubChange(path, str(obj), "{{ph." + name + "}}", "identifier"))
            return "{{ph." + name + "}}"
        return obj


def scrub(profile: Profile) -> tuple[Profile, list[ScrubChange]]:
    s = _Scrubber(profile)
    data = profile.model_dump(mode="json")
    s.detect(data)
    data = s.rewrite(data, "")
    # Capture names may contain user or host names; evidence keeps only stable indices.
    names = {c["name"]: f"capture-{i + 1}" for i, c in enumerate(data["provenance"]["captures"])}
    for i, cap in enumerate(data["provenance"]["captures"]):
        s.changes.append(ScrubChange(f"provenance.captures.{i}", cap["name"], names[cap["name"]], "capture name"))
        cap["name"] = names[cap["name"]]
        cap["sha256"] = "scrubbed"

    def fix_evidence(obj: Any) -> None:
        if isinstance(obj, dict):
            if set(obj) == {"capture", "flow", "message"} and isinstance(obj["capture"], str):
                obj["capture"] = names.get(obj["capture"], "capture")
            for v in obj.values():
                fix_evidence(v)
        elif isinstance(obj, list):
            for v in obj:
                fix_evidence(v)

    fix_evidence(data)
    hosts = data["revivability"]["hosts"]
    if hosts:
        t0 = min(h["first_seen"] for h in hosts)
        for h in hosts:
            h["first_seen"] = round(h["first_seen"] - t0, 3)
            h["last_seen"] = round(h["last_seen"] - t0, 3)
    data["placeholders"] = {k: v.model_dump(mode="json") for k, v in s.placeholders.items()}
    for ph in data["placeholders"].values():
        src = ph.get("source")
        if src and src.get("pattern"):
            src["pattern"] = s.rewrite(src["pattern"], "", "pattern")
    data["provenance"]["scrubbed"] = True
    return Profile.model_validate(data), s.changes


def identifiers_in(profile: Profile) -> list[str]:
    """Literal values a scrubbed profile must not contain (used by tests and export checks)."""
    return [str(p.value) for p in profile.placeholders.values() if isinstance(p.value, str) and p.value]
