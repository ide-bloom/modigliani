"""Path and topic templates, and response templatization.

Path rule: a segment becomes a parameter when it looks like an identifier (see
values.is_identifier) or equals a known identifier value. Plain words never become
parameters, so /status and /commands stay distinct endpoints. Parameter names come from known values first (a segment equal to the `serial`
field of the login body is called `serial`), then from the preceding segment
(`devices/{device_id}`).
"""

from __future__ import annotations

import itertools
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from modigliani.infer.values import (
    Scalar,
    flatten,
    is_identifier,
    singular,
    snake,
    time_kind,
    token_format,
)


@dataclass
class TemplateMatch:
    template: str
    params: dict[str, str]


def _param_name(prev: str | None, value: str, known: dict[str, str], used: set[str]) -> str:
    for name, known_value in known.items():
        if known_value == value and name not in used:
            return name
    base = f"{singular(snake(prev))}_id" if prev and not is_identifier(prev) else "id"
    if base in ("_id", "id_id"):
        base = "id"
    name, n = base, 2
    while name in used:
        name, n = f"{base}{n}", n + 1
    return name


def infer_templates(items: list[str], sep: str, known: dict[str, str] | None = None) -> dict[str, TemplateMatch]:
    """Infer templates for '/'-separated paths or topics. Returns item -> match."""
    known = known or {}
    result: dict[str, TemplateMatch] = {}
    for item in sorted(set(items)):
        segs = item.split(sep)
        used: set[str] = set()
        out: list[str] = []
        params: dict[str, str] = {}
        for i, s in enumerate(segs):
            known_hit = any(v == s for v in known.values()) and len(s) >= 3
            if s and (is_identifier(s) or known_hit):
                name = _param_name(segs[i - 1] if i else None, s, known, used)
                used.add(name)
                params[name] = s
                out.append("{" + name + "}")
            else:
                out.append(s)
        result[item] = TemplateMatch(sep.join(out), params)
    return result


def pattern_from_value(value: str, known: dict[str, str]) -> str:
    """Turn a concrete string into a template by replacing known identifier values."""
    out = value
    for name, v in sorted(known.items(), key=lambda kv: -len(kv[1])):
        if v and len(v) >= 3 and v in out:
            out = out.replace(v, "{" + name + "}")
    return out


@dataclass
class TemplContext:
    """What a response value may be derived from."""

    ts: float
    path_params: dict[str, str] = field(default_factory=dict)
    query: dict[str, str] = field(default_factory=dict)
    body: dict[str, Scalar] = field(default_factory=dict)
    token: str | None = None
    token_lifetime: int | None = None
    # Other observed values for the same response position (for detecting generated values).
    siblings: dict[str, list[Scalar]] = field(default_factory=dict)
    placeholders: dict[str, str] = field(default_factory=dict)
    # Paths whose value should come from state, e.g. {"power": "state.power"}.
    state_paths: dict[str, str] = field(default_factory=dict)
    request_prefix: str = "req.body"


def _generated(values: list[Scalar]) -> str | None:
    distinct = {v for v in values if v is not None}
    if len(distinct) < 2 or len(distinct) < len(values) * 0.6:
        return None
    if all(isinstance(v, int) and not isinstance(v, bool) for v in values):
        ints = [v for v in values if isinstance(v, int)]
        if all(b > a for a, b in itertools.pairwise(ints)):
            return "{{gen.seq}}"
        return None
    if all(isinstance(v, str) for v in distinct):
        fmts = {token_format(str(v)) for v in distinct}
        if fmts == {"uuid"}:
            return "{{gen.uuid}}"
        if fmts == {"hex"}:
            length = len(str(next(iter(distinct))))
            return "{{gen.hex." + str(length) + "}}"
        if fmts <= {"alnum", "base64url"} and None not in fmts:
            length = len(str(next(iter(distinct))))
            return "{{gen.alnum." + str(length) + "}}"
    return None


def templatize(value: Any, ctx: TemplContext, path: str = "") -> Any:
    if isinstance(value, dict):
        return {k: templatize(v, ctx, f"{path}.{k}" if path else str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [templatize(v, ctx, f"{path}.{i}" if path else str(i)) for i, v in enumerate(value)]
    return _template_leaf(value, ctx, path)


def _template_leaf(value: Scalar, ctx: TemplContext, path: str) -> Any:
    if path in ctx.state_paths:
        return "{{" + ctx.state_paths[path] + "}}"
    if isinstance(value, str) and ctx.token and value == ctx.token:
        return "{{token.value}}"
    if isinstance(value, str) and ctx.token and ctx.token in value:
        return value.replace(ctx.token, "{{token.value}}")
    key = path.rsplit(".", 1)[-1].lower()
    if (
        ctx.token_lifetime is not None
        and isinstance(value, int)
        and value == ctx.token_lifetime
        and ("exp" in key or "ttl" in key or "lifetime" in key)
    ):
        return "{{token.expires_in}}"
    if isinstance(value, str) and len(value) >= 3:
        for name, v in ctx.path_params.items():
            if value == v:
                return "{{req.path." + name + "}}"
        for qk, qv in ctx.query.items():
            if value == qv:
                return "{{req.query." + qk + "}}"
        for bp, bv in ctx.body.items():
            if isinstance(bv, str) and value == bv:
                return "{{" + ctx.request_prefix + "." + bp + "}}"
        for name, v in ctx.placeholders.items():
            if value == v:
                return "{{ph." + name + "}}"
    kind = time_kind(value, ctx.ts)
    if kind is not None and not isinstance(value, bool):
        return "{{now." + kind + "}}"
    siblings = ctx.siblings.get(path)
    if siblings:
        gen = _generated(siblings)
        if gen:
            return gen
    return value


def sibling_values(bodies: list[Any]) -> dict[str, list[Scalar]]:
    out: dict[str, list[Scalar]] = defaultdict(list)
    for b in bodies:
        for p, v in flatten(b).items():
            out[p].append(v)
    return dict(out)


def most_common_shape(bodies: list[Any]) -> Any:
    """Pick the most frequent body by its set of keys, preferring the first such body."""
    if not bodies:
        return None
    shapes = Counter(tuple(sorted(flatten(b).keys())) for b in bodies)
    best = shapes.most_common(1)[0][0]
    for b in bodies:
        if tuple(sorted(flatten(b).keys())) == best:
            return b
    return bodies[0]
