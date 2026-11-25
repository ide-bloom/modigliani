"""Authentication flow detection.

Login rule (docs/inference.md, "Authentication flows"): a response value that is shaped like
a token (values.token_format) and is later presented by the device in a header, query
parameter or body marks that response's endpoint as the token issuer. Lifetime comes from
an `expires_in`/`ttl`/`exp`-like field next to it, from the JWT `exp - iat`, or from the
observed interval between logins.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from modigliani.infer.sessions import HttpExchange, Ref
from modigliani.infer.values import flatten, jwt_lifetime, parse_body, token_format

_LIFETIME_KEYS = ("expires_in", "expiresin", "expires", "ttl", "lifetime", "expiry", "valid_for", "exp_in")


@dataclass
class TokenFinding:
    issuer_index: int  # index into the exchange list
    token: str
    format: str
    prefix: str
    length: int
    location: str  # bearer | header | query | body
    name: str
    lifetime_s: int | None
    token_path: str
    refs: list[Ref]


def _usage(ex: HttpExchange, token: str) -> tuple[str, str] | None:
    for k, v in ex.req.headers:
        if k.lower() == "authorization" and v.split()[-1] == token:
            return ("bearer", "Authorization") if v.lower().startswith("bearer ") else ("header", k)
        if v == token:
            return "header", k
    for k, vs in ex.req.query.items():
        if token in vs:
            return "query", k
    body = parse_body(ex.req.header("content-type"), ex.req.body)
    for path, bv in flatten(body).items():
        if bv == token:
            return "body", path
    return None


def detect_token_auth(exchanges: list[HttpExchange]) -> TokenFinding | None:
    ordered = sorted(range(len(exchanges)), key=lambda i: exchanges[i].ts)
    for pos, i in enumerate(ordered):
        ex = exchanges[i]
        if ex.resp is None or ex.resp.status >= 400:
            continue
        body = parse_body(ex.resp.header("content-type"), ex.resp.body)
        flat = flatten(body)
        for path, value in flat.items():
            if not isinstance(value, str):
                continue
            fmt = token_format(value)
            keyname = path.rsplit(".", 1)[-1].lower()
            if fmt is None and not any(k in keyname for k in ("token", "session", "jwt")):
                continue
            if fmt is None:
                fmt = "alnum"
            uses: list[tuple[HttpExchange, tuple[str, str]]] = []
            for j in ordered[pos + 1 :]:
                u = _usage(exchanges[j], value)
                if u:
                    uses.append((exchanges[j], u))
            if not uses:
                continue
            location, name = uses[0][1]
            lifetime = None
            parent = path.rsplit(".", 1)[0] if "." in path else ""
            for p2, v2 in flat.items():
                p2_parent = p2.rsplit(".", 1)[0] if "." in p2 else ""
                key2 = p2.rsplit(".", 1)[-1].lower().replace("-", "_")
                if p2_parent == parent and isinstance(v2, int) and not isinstance(v2, bool):
                    if any(key2 == k or key2.endswith("_" + k) for k in _LIFETIME_KEYS):
                        lifetime = v2
            if lifetime is None and fmt == "jwt":
                lifetime = jwt_lifetime(value)
            if lifetime is None:
                logins = [exchanges[k].ts for k in ordered if _same_endpoint(exchanges[k], ex)]
                if len(logins) >= 2:
                    gaps = [b - a for a, b in itertools.pairwise(logins)]
                    lifetime = int(min(gaps))
            prefix = ""
            if fmt in ("alnum", "base64url") and "_" in value[:12]:
                prefix = value[: value.index("_") + 1]
            return TokenFinding(
                issuer_index=i,
                token=value,
                format=fmt,
                prefix=prefix,
                length=len(value) - len(prefix),
                location=location,
                name=name,
                lifetime_s=lifetime,
                token_path=path,
                refs=[ex.ref] + [u[0].ref for u in uses[:3]],
            )
    return None


def _same_endpoint(a: HttpExchange, b: HttpExchange) -> bool:
    return a.req.method == b.req.method and a.req.path == b.req.path
