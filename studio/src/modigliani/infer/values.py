"""Value-level heuristics shared by the inference rules.

Each heuristic is documented in docs/inference.md. They are intentionally conservative:
a false "this is an identifier" only produces an extra parameter, while a false "this is
a constant" would bake one user's identifier into a shared profile.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs

Scalar = bool | int | float | str | None

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_B64URL = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")
_B64STD = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)
_VERSION_SEG = re.compile(r"^v\d+(\.\d+)*$", re.IGNORECASE)
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")


def flatten(obj: Any, prefix: str = "") -> dict[str, Scalar]:
    """Flatten JSON into dotted paths; list indices are numeric segments (a.0.b)."""
    out: dict[str, Scalar] = {}
    if isinstance(obj, dict):
        if not obj and prefix:
            return out
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else str(k)))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(flatten(v, f"{prefix}.{i}" if prefix else str(i)))
    elif obj is None or isinstance(obj, bool | int | float | str):
        out[prefix] = obj
    return out


def get_path(obj: Any, path: str) -> Any:
    if path == "":
        return obj
    cur = obj
    for seg in path.split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return None
    return cur


def set_path(obj: Any, path: str, value: Any) -> Any:
    if path == "":
        return value
    segs = path.split(".")
    cur = obj
    for seg in segs[:-1]:
        cur = cur[int(seg)] if isinstance(cur, list) else cur[seg]
    last = segs[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value
    return obj


def walk_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}.{i}" if path else str(i))
    elif isinstance(obj, str):
        yield path, obj


def parse_body(content_type: str | None, body: bytes) -> Any:
    """Return JSON or form data as Python values, or None for other bodies."""
    if not body:
        return None
    ct = (content_type or "").lower()
    text: str
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "json" in ct or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except ValueError:
            return None
    if "x-www-form-urlencoded" in ct or ("=" in text and "&" in text and " " not in text):
        parsed = parse_qs(text, keep_blank_values=True)
        return {k: (v[0] if len(v) == 1 else v) for k, v in parsed.items()}
    return None


def token_format(value: str) -> str | None:
    """Classify token-shaped strings: uuid, jwt, hex, base64url, alnum. None if not token-like."""
    if len(value) < 16 or " " in value:
        return None
    if _UUID.match(value):
        return "uuid"
    parts = value.split(".")
    if len(parts) == 3 and all(_B64URL.match(p) for p in parts):
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            if isinstance(header, dict) and "alg" in header:
                return "jwt"
        except (ValueError, binascii.Error):
            pass
    if _HEX.match(value) and len(value) >= 16:
        return "hex"
    has_digit = any(c.isdigit() for c in value)
    has_alpha = any(c.isalpha() for c in value)
    if value.isalnum() and has_digit and has_alpha and len(value) >= 20:
        return "alnum"
    if (_B64URL.match(value) or _B64STD.match(value)) and has_digit and has_alpha and len(value) >= 20:
        return "base64url"
    return None


def jwt_lifetime(token: str) -> int | None:
    try:
        payload_b64 = token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except (IndexError, ValueError, binascii.Error):
        return None
    if isinstance(payload, dict) and isinstance(payload.get("exp"), int):
        iat = payload.get("iat")
        if isinstance(iat, int):
            return int(payload["exp"]) - iat
    return None


def is_identifier(seg: str) -> bool:
    """Does a path/topic segment look like a per-device or per-user identifier?"""
    if not seg or _VERSION_SEG.match(seg):
        return False
    if _UUID.match(seg) or _MAC.match(seg):
        return True
    if seg.isdigit():
        return len(seg) >= 3 or seg not in {"0", "1", "2"}
    has_digit = any(c.isdigit() for c in seg)
    if _HEX.match(seg) and len(seg) >= 8 and has_digit:
        return True
    if has_digit and len(seg) >= 5 and re.fullmatch(r"[A-Za-z0-9_\-:.]+", seg):
        return any(c.isalpha() for c in seg) or "-" in seg
    return False


def is_mac(value: str) -> bool:
    return bool(_MAC.match(value))


def time_kind(value: Scalar, ref_ts: float) -> str | None:
    """Is this value the current time? Returns 'unix', 'unix_ms', 'iso' or None.

    A two-day window absorbs device clocks that are off and captures replayed later.
    """
    window = 2 * 86400
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        if abs(value) < 1e8:  # before 1973: a reading or counter, never a clock
            return None
        if abs(value - ref_ts) < window:
            return "unix"
        if abs(value / 1000.0 - ref_ts) < window:
            return "unix_ms"
        return None
    if isinstance(value, str) and _ISO.match(value):
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.UTC)
        if abs(parsed.timestamp() - ref_ts) < window:
            return "iso"
    return None


def snake(name: str) -> str:
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    name = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower()
    if not name:
        return "value"
    if name[0].isdigit():
        name = "f_" + name
    return name


def leaf_name(path: str) -> str:
    segs = [s for s in path.split(".") if s and not s.isdigit()]
    return snake(segs[-1]) if segs else "value"


def singular(word: str) -> str:
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith("ses"):
        return word[:-2]
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word
