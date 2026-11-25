"""The inference engine: captures + annotations -> device profile with evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import itertools
import json
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, cast

from modigliani import __version__
from modigliani.annotate.model import Annotation, AnnotationKind
from modigliani.capture.model import Capture, Direction, TlsOutcome
from modigliani.infer import frames as fr
from modigliani.infer.auth import TokenFinding, detect_token_auth
from modigliani.infer.decoders import CoapMessage
from modigliani.infer.schema import infer_schema
from modigliani.infer.sessions import CoapEvent, DeviceSessions, HttpExchange, Ref, build_sessions
from modigliani.infer.state import FieldSeries, Obs, VariableEvidence, correlate
from modigliani.infer.templates import (
    TemplContext,
    infer_templates,
    most_common_shape,
    pattern_from_value,
    sibling_values,
    templatize,
)
from modigliani.infer.values import (
    Scalar,
    flatten,
    get_path,
    is_identifier,
    is_mac,
    parse_body,
    snake,
)
from modigliani.profile import model as pm

_IDENTITY_KEYS = ("serial", "sn", "serial_number", "device_id", "deviceid", "did", "uuid", "mac", "device", "id")
_FIRMWARE_WORDS = ("firmware", "fw", "ota", "update", "upgrade")
_TIME_WORDS = ("time", "clock", "ntp", "date", "epoch", "sync")
_HA_MODES = {
    "off": "off",
    "heat": "heat",
    "heating": "heat",
    "cool": "cool",
    "cooling": "cool",
    "auto": "auto",
    "automatic": "auto",
    "dry": "dry",
    "dehumidify": "dry",
    "fan": "fan_only",
    "fan_only": "fan_only",
    "heat_cool": "heat_cool",
}


@dataclass
class InferenceResult:
    profile: pm.Profile
    summary: list[str] = field(default_factory=list)

    @property
    def revivable(self) -> bool:
        return self.profile.revivability.status != "not_revivable_without_firmware_access"


def _ev(refs: list[Ref], limit: int = 5) -> list[pm.Evidence]:
    seen: list[pm.Evidence] = []
    for r in refs:
        e = pm.Evidence(capture=r.capture, flow=r.flow, message=r.message)
        if e not in seen:
            seen.append(e)
        if len(seen) >= limit:
            break
    return seen


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s or "device"


def _words(template: str) -> list[str]:
    plain = re.sub(r"\{[^}]*\}", "", template.lower())
    return [w for w in re.split(r"[/_.\-]+", plain) if w]


@dataclass
class _HttpGroup:
    id: str
    host: str
    method: str
    template: str
    exchanges: list[tuple[HttpExchange, dict[str, str]]] = field(default_factory=list)


@dataclass
class _Ctx:
    sess: DeviceSessions
    annotations: list[Annotation]
    known: dict[str, str] = field(default_factory=dict)
    known_source: dict[str, pm.PlaceholderSource] = field(default_factory=dict)
    series: dict[tuple[str, str], FieldSeries] = field(default_factory=dict)
    excluded: set[tuple[str, str]] = field(default_factory=set)
    summary: list[str] = field(default_factory=list)

    def observe(
        self, channel: str, path: str, direction: Direction, ts: float, value: Scalar, ref: Ref, name: str | None = None
    ) -> None:
        key = (channel, path)
        s = self.series.get(key)
        if s is None:
            s = self.series[key] = FieldSeries(channel, path, direction, name=name)
        s.obs.append(Obs(ts, value, ref))


def infer_profile(
    captures: list[Capture],
    annotations: list[Annotation],
    device: str | None = None,
    profile_id: str | None = None,
    name: str | None = None,
) -> InferenceResult:
    sess = build_sessions(captures, device)
    ctx = _Ctx(sess=sess, annotations=sorted(annotations, key=lambda a: a.ts))
    hosts = _host_reports(captures, device)
    revivability = _revivability(sess, hosts)
    dev_name = name or sess.device
    pid = profile_id or _slug(dev_name)
    provenance = pm.Provenance(
        generated_by=f"modigliani {__version__}",
        created=dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        captures=[
            pm.CaptureRef(name=c.name, sha256=hashlib.sha256(c.model_dump_json().encode()).hexdigest(), mode=c.mode)
            for c in captures
        ],
    )
    names = sorted({h.host for h in hosts if not re.fullmatch(r"[\d.]+|[0-9a-f:]+", h.host)} | sess.dns_names)
    profile = pm.Profile(id=pid, name=dev_name, revivability=revivability, provenance=provenance)
    profile.dns = pm.DnsConfig(names=names)
    profile.device.fingerprints += [pm.Fingerprint(kind="sni", pattern="^" + re.escape(n) + "$") for n in names]

    if revivability.status == "not_revivable_without_firmware_access":
        profile.tls = pm.TlsConfig(mode="strict_verification", hostnames=names)
        ctx.summary.append("Device is NOT revivable without firmware access:")
        ctx.summary += [f"  - {r}" for r in revivability.reasons]
        return InferenceResult(profile, ctx.summary)

    accepted = sorted({h.host for h in hosts if h.tls_outcome == TlsOutcome.ACCEPTED_LOCAL_CA.value})
    rejected = any(h.tls_outcome in (TlsOutcome.REJECTED_LOCAL_CA.value, TlsOutcome.PASSTHROUGH.value) for h in hosts)
    if rejected:
        mode: str = "mixed"
    elif accepted:
        mode = "local_ca"
    else:
        mode = "none"
    profile.tls = pm.TlsConfig(mode=cast(Any, mode), hostnames=accepted)

    _collect_known_identifiers(ctx)
    http_groups = _http_groups(ctx)
    token = detect_token_auth(sess.http)
    mqtt_cfg = _mqtt(ctx)
    coap_frames, coap_handlers = _coap(ctx)
    raw_handlers, raw_frames = _raw(ctx)
    ws_handlers = _websocket(ctx)
    http_handlers = _http_handlers(ctx, http_groups, token)

    variables = correlate(list(ctx.series.values()), ctx.annotations, sess.start, ctx.excluded)
    _apply_state(
        ctx, profile, variables, http_handlers, http_groups, mqtt_cfg, coap_handlers, raw_handlers, ws_handlers
    )

    profile.handlers = pm.Handlers(
        http=http_handlers, websocket=ws_handlers, mqtt=mqtt_cfg, coap=coap_handlers, raw=raw_handlers
    )
    profile.frames = coap_frames + raw_frames
    if token is not None:
        issuer = next(g.id for g in http_groups if any(ex is sess.http[token.issuer_index] for ex, _ in g.exchanges))
        profile.auth.token = pm.TokenSpec(
            format=cast(Any, token.format),
            length=token.length,
            prefix=token.prefix,
            lifetime_s=token.lifetime_s,
            location=cast(Any, token.location),
            name=token.name,
            issued_by=issuer,
            evidence=_ev(token.refs),
        )
        ctx.summary.append(
            f"Auth: token issued by {issuer} ({token.format}, lifetime {token.lifetime_s}s, sent as {token.location})"
        )
    if mqtt_cfg is not None and sess.mqtt:
        connect = next((s.connect for s in sess.mqtt if s.connect), None)
        if connect is not None:
            ident = {k: v for k, v in ctx.known.items() if k == mqtt_cfg.identity_var}
            profile.auth.mqtt = pm.MqttAuth(
                client_id_pattern=pattern_from_value(connect.client_id, ident),
                username_pattern=pattern_from_value(connect.username or "", ident),
            )
            profile.auth.notes.append(
                "MQTT passwords are accepted as presented: the vendor's secrets are never needed."
            )
            profile.device.fingerprints.append(
                pm.Fingerprint(
                    kind="mqtt_client_id",
                    pattern=_regex_from_template(profile.auth.mqtt.client_id_pattern),
                    evidence=_ev([e.ref for s in sess.mqtt for e in s.events[:1]]),
                )
            )
    ua = Counter(ex.req.header("user-agent") for ex in sess.http if ex.req.header("user-agent"))
    if ua:
        agent = ua.most_common(1)[0][0] or ""
        profile.device.fingerprints.append(
            pm.Fingerprint(
                kind="http_user_agent",
                pattern="^" + re.sub(r"\\\d+(\\\.\d+)*|\d+(\\\.\d+)*", r"[\\d.]+", re.escape(agent)) + "$",
            )
        )
    for h in coap_handlers:
        profile.device.fingerprints.append(pm.Fingerprint(kind="coap_path", pattern=_regex_from_template(h.path)))

    profile.placeholders = {
        k: pm.Placeholder(
            kind=cast(Any, _placeholder_kind(k, v)),
            value=v,
            description=f"Per-device value '{k}' learned from traffic",
            source=ctx.known_source.get(k),
        )
        for k, v in ctx.known.items()
    }
    profile.home_assistant = _home_assistant(profile)
    ctx.summary.insert(0, f"Revivability: {revivability.status}")
    ctx.summary.append(
        f"Handlers: {len(http_handlers)} HTTP, {len(ws_handlers)} WebSocket, "
        f"{len(mqtt_cfg.topics) if mqtt_cfg else 0} MQTT topics, {len(coap_handlers)} CoAP, {len(raw_handlers)} raw"
    )
    ctx.summary.append(
        "State: "
        + (", ".join(f"{v.name}{'*' if v.writable else ''}" for v in profile.state) or "none")
        + "  (* = writable)"
    )
    ctx.summary.append("Commands: " + (", ".join(f"{c.name} via {c.transport}" for c in profile.commands) or "none"))
    return InferenceResult(profile, ctx.summary)


# ----------------------------------------------------------------------------- TLS and hosts


def _host_reports(captures: list[Capture], device: str | None) -> list[pm.HostReport]:
    agg: dict[tuple[str, int, str], list[Any]] = {}
    for cap in captures:
        for f in cap.flows_for(device):
            host = f.hostname or f.tls.sni or f.server.host
            key = (host, f.server.port, f.tls.outcome.value)
            up = sum(s.size for s in f.segments if s.dir is Direction.UP)
            down = sum(s.size for s in f.segments if s.dir is Direction.DOWN)
            stamps = [s.ts for s in f.segments if s.dir is Direction.UP]
            if key not in agg:
                agg[key] = [0, 0, 0, f.start, f.end, []]
            a = agg[key]
            a[0] += 1
            a[1] += up
            a[2] += down
            a[3] = min(a[3], f.start)
            a[4] = max(a[4], f.end)
            a[5] += stamps
    out = []
    for (host, port, outcome), (n, up, down, first, last, stamps) in sorted(agg.items()):
        stamps = sorted(stamps)
        gaps = [b - a for a, b in itertools.pairwise(stamps) if b - a > 0.05]
        out.append(
            pm.HostReport(
                host=host,
                port=port,
                tls_outcome=outcome,
                flows=n,
                bytes_up=up,
                bytes_down=down,
                first_seen=first,
                last_seen=last,
                mean_interval_s=round(statistics.mean(gaps), 2) if gaps else None,
            )
        )
    return out


def _revivability(sess: DeviceSessions, hosts: list[pm.HostReport]) -> pm.Revivability:
    decodable = bool(sess.http or sess.mqtt or sess.coap or sess.ws or sess.raw)
    rejected = sorted({(h.host, h.port) for h in hosts if h.tls_outcome == TlsOutcome.REJECTED_LOCAL_CA.value})
    untested = sorted({(h.host, h.port) for h in hosts if h.tls_outcome == TlsOutcome.UNTESTED.value})
    reasons: list[str] = []
    for host, port in rejected:
        reasons.append(
            f"{host}:{port}: the device refused the local CA's certificate, so it strictly verifies the "
            "vendor's server certificate. Modigliani never tries to bypass certificate verification; "
            "reviving this connection needs firmware access. Only metadata (hostnames, timing, sizes) was recorded."
        )
    for host, port in untested:
        reasons.append(
            f"{host}:{port}: encrypted traffic was recorded passively. Record again with `--mode proxy` "
            "to test whether the device accepts the local CA."
        )
    if not decodable and rejected:
        status = "not_revivable_without_firmware_access"
    elif not decodable or rejected or untested:
        status = "partial"
    else:
        status = "revivable"
    return pm.Revivability(status=cast(Any, status), reasons=reasons, hosts=hosts)


# ----------------------------------------------------------------------------- identifiers


def _collect_known_identifiers(ctx: _Ctx) -> None:
    """Find per-device identifiers (serials, device ids) so templates can name them."""
    for ex in ctx.sess.http:
        body = parse_body(ex.req.header("content-type"), ex.req.body)
        for path, value in flatten(body).items():
            key = snake(path.rsplit(".", 1)[-1])
            if isinstance(value, str) and (key in _IDENTITY_KEYS or is_mac(value)) and len(value) >= 3:
                if key not in ctx.known:
                    ctx.known[key] = value
                    ctx.known_source[key] = pm.PlaceholderSource(kind="http_body", selector=path)
    for s in ctx.sess.mqtt:
        if s.connect is None:
            continue
        topics = [e.packet.topic for e in s.events if e.packet.type == "PUBLISH"]
        topics += [t for e in s.events for t, _ in e.packet.subscriptions]
        for t in topics:
            for seg in t.split("/"):
                if is_identifier(seg) and (seg in s.connect.client_id or seg == s.connect.username):
                    if seg not in ctx.known.values():
                        ctx.known.setdefault("device_id", seg)
                        ctx.known_source.setdefault(
                            "device_id",
                            pm.PlaceholderSource(
                                kind="mqtt_client_id",
                                pattern=re.escape(s.connect.client_id).replace(re.escape(seg), "(.+)"),
                            ),
                        )


# ----------------------------------------------------------------------------- HTTP


def _http_groups(ctx: _Ctx) -> list[_HttpGroup]:
    exchanges = ctx.sess.http
    tmpl = infer_templates([ex.req.path for ex in exchanges], "/", ctx.known)
    groups: dict[tuple[str, str, str], _HttpGroup] = {}
    used_ids: set[str] = set()
    for ex in sorted(exchanges, key=lambda e: e.ts):
        tm = tmpl[ex.req.path]
        key = (ex.host, ex.req.method, tm.template)
        if key not in groups:
            words = [w for w in _words(tm.template) if w != "api" and not re.fullmatch(r"v\d+", w)]
            base = snake(ex.req.method.lower() + "_" + ("_".join(words) or "root"))
            hid, n = base, 2
            while hid in used_ids:
                hid, n = f"{base}_{n}", n + 1
            used_ids.add(hid)
            groups[key] = _HttpGroup(hid, ex.host, ex.req.method, tm.template)
        groups[key].exchanges.append((ex, tm.params))
    for g in groups.values():
        for ex, params in g.exchanges:
            for pname, pval in params.items():
                ctx.known_source.setdefault(pname, pm.PlaceholderSource(kind="http_path", handler=g.id, selector=pname))
                if pname in ctx.known or any(v == pval for v in ctx.known.values()):
                    continue
                ctx.known[pname] = pval
            req_body = parse_body(ex.req.header("content-type"), ex.req.body)
            for p, v in flatten(req_body).items():
                ctx.observe(f"http:{g.id}:req", "body." + p, Direction.UP, ex.ts, v, ex.ref)
                if isinstance(v, str) and v in ctx.known.values():
                    ctx.excluded.add((f"http:{g.id}:req", "body." + p))
            for qk, qv in ex.req.query.items():
                ctx.observe(f"http:{g.id}:req", "query." + qk, Direction.UP, ex.ts, qv[0] if qv else None, ex.ref)
            if ex.resp is not None:
                body = parse_body(ex.resp.header("content-type"), ex.resp.body)
                for p, v in flatten(body).items():
                    ctx.observe(f"http:{g.id}:resp", "body." + p, Direction.DOWN, ex.resp_ts or ex.ts, v, ex.ref)
    return list(groups.values())


def _identity_for(params: dict[str, str], body: Any, ctx: _Ctx) -> str | None:
    for pname, pval in params.items():
        if pval in ctx.known.values():
            return f"req.path.{pname}"
    if params:
        return f"req.path.{next(iter(params))}"
    for p, v in flatten(body).items():
        if isinstance(v, str) and v in ctx.known.values():
            return f"req.body.{p}"
    return None


def _http_handlers(ctx: _Ctx, groups: list[_HttpGroup], token: TokenFinding | None) -> list[pm.HttpHandler]:
    handlers: list[pm.HttpHandler] = []
    token_ex = ctx.sess.http[token.issuer_index] if token else None
    for g in groups:
        exs = [ex for ex, _ in g.exchanges]
        params0 = g.exchanges[0][1]
        req_bodies = [parse_body(ex.req.header("content-type"), ex.req.body) for ex in exs]
        resp_bodies = [parse_body(ex.resp.header("content-type"), ex.resp.body) if ex.resp else None for ex in exs]
        words = _words(g.template)
        housekeeping: str | None = None
        if any(w in _FIRMWARE_WORDS for w in words):
            housekeeping = "firmware_check"
        elif any(w in _TIME_WORDS for w in words):
            housekeeping = "time_sync"
        auth = "none"
        if token_ex is not None and any(ex is token_ex for ex in exs):
            auth = "issue_token"
        elif (
            token is not None
            and all(_presents(ex, token.token) or ex.ts < token_ex.ts for ex in exs if token_ex)
            and any(_presents(ex, token.token) for ex in exs)
        ):
            auth = "token"
        statuses = Counter(ex.resp.status for ex in exs if ex.resp)
        status = statuses.most_common(1)[0][0] if statuses else 200
        ctype = next((ex.resp.header("content-type") for ex in exs if ex.resp and ex.resp.header("content-type")), None)
        body_type = "empty"
        bodies = [b for b in resp_bodies if b is not None]
        if bodies:
            body_type = "json" if isinstance(bodies[0], dict | list) and "form" not in (ctype or "") else "form"
        elif any(ex.resp and ex.resp.body for ex in exs):
            body_type = "text"
        template_body: Any = None
        if bodies:
            idx = resp_bodies.index(most_common_shape(bodies))
            ex = exs[idx]
            tctx = TemplContext(
                ts=ex.resp_ts or ex.ts,
                path_params=g.exchanges[idx][1],
                query={k: v[0] for k, v in ex.req.query.items() if v},
                body=dict(flatten(req_bodies[idx]).items()),
                token=token.token if auth == "issue_token" and token else None,
                token_lifetime=token.lifetime_s if token else None,
                siblings=sibling_values(bodies),
                placeholders=ctx.known,
            )
            template_body = templatize(resp_bodies[idx], tctx)
            if housekeeping == "firmware_check":
                template_body = _no_update(template_body)
        elif body_type == "text":
            first = next(ex for ex in exs if ex.resp and ex.resp.body)
            assert first.resp is not None
            template_body = first.resp.body.decode("utf-8", "replace")
        headers = {}
        if ctype:
            headers["Content-Type"] = ctype
        stamps = sorted(ex.ts for ex in exs)
        gaps = [b - a for a, b in itertools.pairwise(stamps)]
        handlers.append(
            pm.HttpHandler(
                id=g.id,
                host=g.host,
                method=g.method,
                path=g.template,
                identity=_identity_for(params0, req_bodies[0], ctx),
                auth=cast(Any, auth),
                request_schema=infer_schema(req_bodies),
                response=pm.HttpResponseSpec(
                    status=status, headers=headers, body_type=cast(Any, body_type), body=template_body
                ),
                housekeeping=cast(Any, housekeeping),
                polling_interval_s=round(statistics.median(gaps), 2) if len(gaps) >= 2 else None,
                evidence=_ev([ex.ref for ex in exs]),
            )
        )
    return handlers


def _presents(ex: HttpExchange, token: str) -> bool:
    if any(token in v for _, v in ex.req.headers):
        return True
    return token in ex.req.target or token.encode() in ex.req.body


def _no_update(body: Any) -> Any:
    """Force a firmware check response to say 'no update' (housekeeping rule)."""
    if isinstance(body, dict):
        out: dict[str, Any] = {}
        for k, v in body.items():
            low = k.lower()
            if isinstance(v, bool) and any(w in low for w in ("update", "avail", "new", "upgrade")):
                out[k] = False
            elif isinstance(v, str) and any(w in low for w in ("url", "link", "download")):
                out[k] = ""
            else:
                out[k] = _no_update(v)
        return out
    if isinstance(body, list):
        return [_no_update(v) for v in body]
    return body


# ----------------------------------------------------------------------------- MQTT


def _payload(data: bytes) -> tuple[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", None
    try:
        return "json", json.loads(text)
    except ValueError:
        return "text", text


def _mqtt(ctx: _Ctx) -> pm.MqttConfig | None:
    sessions = ctx.sess.mqtt
    if not sessions:
        return None
    pubs = [(s, e) for s in sessions for e in s.events if e.packet.type == "PUBLISH"]
    subs = [t for s in sessions for e in s.events for t, _ in e.packet.subscriptions]
    tmpl = infer_templates([e.packet.topic for _, e in pubs] + subs, "/", ctx.known)
    identity_var = "device_id" if "device_id" in ctx.known else None
    topics: dict[tuple[str, str], pm.MqttTopic] = {}
    publishes: dict[str, list[tuple[float, Any, Ref, dict[str, str]]]] = defaultdict(list)
    used: set[str] = set()

    def topic_id(template: str, direction: str) -> str:
        words = list(_words(template)) or ["topic"]
        base = snake("_".join(words[-2:]) if len(words) > 1 else words[0])
        if direction == "cloud_to_device" and base in used:
            base += "_down"
        tid, n = base, 2
        while tid in used:
            tid, n = f"{base}_{n}", n + 1
        used.add(tid)
        return tid

    for _, e in sorted(pubs, key=lambda se: se[1].ts):
        tm = tmpl[e.packet.topic]
        direction = "device_to_cloud" if e.dir is Direction.UP else "cloud_to_device"
        key = (tm.template, direction)
        ptype, payload = _payload(e.packet.payload)
        if key not in topics:
            topics[key] = pm.MqttTopic(
                id=topic_id(tm.template, direction),
                topic=tm.template,
                direction=cast(Any, direction),
                payload_type=cast(Any, ptype),
            )
        t = topics[key]
        t.qos = max(t.qos, e.packet.qos)
        t.retain = t.retain or e.packet.retain
        if len(t.evidence) < 5:
            t.evidence.append(pm.Evidence(capture=e.ref.capture, flow=e.ref.flow, message=e.ref.message))
        publishes[t.id].append((e.ts, payload, e.ref, tm.params))
        for p, v in flatten(payload).items():
            ctx.observe(f"mqtt:{t.id}", "payload." + p, e.dir, e.ts, v, e.ref)
    for filt in subs:
        tm = tmpl[filt]
        key = (tm.template, "cloud_to_device")
        if key not in topics:
            topics[key] = pm.MqttTopic(
                id=topic_id(tm.template, "cloud_to_device"), topic=tm.template, direction="cloud_to_device"
            )
    by_id = {t.id: t for t in topics.values()}
    # Request/response rule: every publish on a cloud topic follows a device publish on one topic
    # within 1.5 s, and most publishes on that device topic get such an answer.
    for down in [t for t in topics.values() if t.direction == "cloud_to_device"]:
        dpubs = publishes.get(down.id, [])
        if not dpubs:
            continue
        for up in [t for t in topics.values() if t.direction == "device_to_cloud"]:
            upubs = publishes.get(up.id, [])
            if not upubs:
                continue
            answered = [any(0 <= dt_ - ut <= 1.5 for dt_, *_ in dpubs) for ut, *_ in upubs]
            follows = all(any(0 <= dt_ - ut <= 1.5 for ut, *_ in upubs) for dt_, *_ in dpubs)
            if follows and sum(answered) >= max(1, 0.8 * len(upubs)):
                down.reply_to = up.id
                ts, payload, _, params = dpubs[0]
                req = next((p for ut, p, *_ in reversed(upubs) if ut <= ts), None)
                tctx = TemplContext(
                    ts=ts,
                    path_params=params,
                    body=flatten(req),
                    placeholders=ctx.known,
                    siblings=sibling_values([p for _, p, *_ in dpubs]),
                    request_prefix="req.payload",
                )
                down.payload = templatize(payload, tctx)
                words = _words(down.topic) + _words(up.topic)
                if any(w in _TIME_WORDS for w in words):
                    down.housekeeping = "time_sync"
                elif any(w in _FIRMWARE_WORDS for w in words):
                    down.housekeeping = "firmware_check"
                    down.payload = _no_update(down.payload)
                # Answers are generated by the server, not state: keep them out of correlation.
                for k in list(ctx.series):
                    if k[0] == f"mqtt:{down.id}":
                        ctx.excluded.add(k)
                break
    for t in topics.values():
        samples = [p for _, p, *_ in publishes.get(t.id, []) if p is not None and t.payload_type == "json"]
        t.payload_schema = infer_schema(samples)
        if identity_var:
            for k in list(ctx.series):
                if k[0] == f"mqtt:{t.id}" and any(o.value == ctx.known[identity_var] for o in ctx.series[k].obs):
                    ctx.excluded.add(k)
    if identity_var:
        t0 = next((t for t in topics.values() if f"{{{identity_var}}}" in t.topic), None)
        if t0 is not None and ctx.known_source.get(identity_var) is None:
            ctx.known_source[identity_var] = pm.PlaceholderSource(
                kind="mqtt_topic", handler=t0.id, selector=identity_var
            )
    keepalives = [s.connect.keepalive for s in sessions if s.connect]
    levels = sorted({s.level for s in sessions})
    ctx.summary.append(f"MQTT: {len(by_id)} topics on {', '.join(sorted({s.host for s in sessions}))}")
    return pm.MqttConfig(
        hosts=sorted({s.host for s in sessions}),
        ports=sorted({s.port for s in sessions}),
        tls=any(s.tls for s in sessions),
        protocol_levels=levels,
        keepalive_s=keepalives[0] if keepalives else None,
        identity_var=identity_var,
        topics=sorted(topics.values(), key=lambda t: t.id),
        evidence=_ev([s.events[0].ref for s in sessions if s.events]),
    )


# ----------------------------------------------------------------------------- binary hints


def _hints(annotations: list[Annotation], direction: Direction) -> list[fr.NumericHint]:
    out: list[fr.NumericHint] = []
    for a in annotations:
        if isinstance(a.value, bool):
            value, is_bool = (1.0 if a.value else 0.0), True
        elif isinstance(a.value, int | float):
            value, is_bool = float(a.value), False
        else:
            continue
        if a.kind is AnnotationKind.READING and direction is Direction.DOWN:
            continue
        name = snake(a.variable) if a.variable else ("power" if is_bool else "value")
        if a.kind is AnnotationKind.READING:
            out.append(fr.NumericHint(a.ts, value, name, is_bool, lo=-15.0, hi=5.0))
        elif direction is Direction.DOWN:
            out.append(fr.NumericHint(a.ts, value, name, is_bool, lo=-2.0, hi=15.0))
        else:
            out.append(fr.NumericHint(a.ts, value, name, is_bool, lo=0.0, hi=30.0))
    return out


# ----------------------------------------------------------------------------- CoAP


def _coap(ctx: _Ctx) -> tuple[list[pm.Frame], list[pm.CoapHandler]]:
    events = ctx.sess.coap
    if not events:
        return [], []
    reqs = [e for e in events if e.dir is Direction.UP and e.msg.is_request]
    pairs: list[tuple[CoapEvent, CoapEvent | None]] = []
    downs = [e for e in events if e.dir is Direction.DOWN and not e.msg.is_request]
    for r in reqs:
        resp = next(
            (
                d
                for d in downs
                if d.ts >= r.ts - 0.01
                and d.msg.token == r.msg.token
                and (d.msg.mid == r.msg.mid or d.msg.mtype != "ACK")
            ),
            None,
        )
        pairs.append((r, resp))
    tmpl = infer_templates([r.msg.path for r in reqs], "/", ctx.known)
    groups: dict[tuple[str, str], list[tuple[CoapEvent, CoapEvent | None, dict[str, str]]]] = defaultdict(list)
    for r, resp in pairs:
        tm = tmpl[r.msg.path]
        groups[(r.msg.method, tm.template)].append((r, resp, tm.params))
    binary = [m.payload for e in events for m in [e.msg] if m.payload and _payload(m.payload)[0] == "binary"]
    checksum = fr.find_checksum(binary)
    length_field = _family_length_field(binary, checksum)
    frames: list[pm.Frame] = []
    handlers: list[pm.CoapHandler] = []
    used: set[str] = set()
    for (method, template), items in groups.items():
        words = _words(template) or ["root"]
        hid = base = snake(method.lower() + "_" + "_".join(words))
        n = 2
        while hid in used:
            hid, n = f"{base}_{n}", n + 1
        used.add(hid)
        params0 = items[0][2]
        identity = None
        for pname, pval in params0.items():
            identity = f"req.path.{pname}"
            if pname not in ctx.known and pval not in ctx.known.values():
                ctx.known[pname] = pval
            ctx.known_source.setdefault(pname, pm.PlaceholderSource(kind="coap_path", handler=hid, selector=pname))
            break
        handler = pm.CoapHandler(
            id=hid, method=method, path=template, identity=identity, evidence=_ev([r.ref for r, _, _ in items])
        )
        words_all = _words(template)
        if any(w in _FIRMWARE_WORDS for w in words_all):
            handler.housekeeping = "firmware_check"
        elif any(w in _TIME_WORDS for w in words_all):
            handler.housekeeping = "time_sync"
        stamps = [r.ts for r, _, _ in items]
        gaps = [b - a for a, b in itertools.pairwise(stamps)]
        handler.polling_interval_s = round(statistics.median(gaps), 2) if len(gaps) >= 2 else None
        # Requests
        req_msgs = [(r.ts, r.msg, r.ref) for r, _, _ in items]
        req_layout = _coap_payloads(
            ctx, f"coap:{hid}:req", f"{hid}_req", req_msgs, Direction.UP, checksum, frames, length_field
        )
        handler.request_frame = req_layout.id if req_layout else None
        # Responses
        resp_msgs = [(resp.ts, resp.msg, resp.ref) for _, resp, _ in items if resp is not None]
        codes = Counter(m.code_str for _, m, _ in resp_msgs)
        handler.response.code = codes.most_common(1)[0][0] if codes else "2.05"
        if resp_msgs:
            handler.response.content_format = resp_msgs[0][1].content_format
            resp_layout = _coap_payloads(
                ctx, f"coap:{hid}:resp", f"{hid}_resp", resp_msgs, Direction.DOWN, checksum, frames, length_field
            )
            if resp_layout is not None:
                handler.response.payload_type = "frame"
                handler.response.frame = pm.FramePayload(frame=resp_layout.id)
            else:
                kind, sample = _payload(resp_msgs[0][1].payload)
                if not resp_msgs[0][1].payload:
                    handler.response.payload_type = "empty"
                elif kind == "json":
                    req_sample = _payload(items[0][0].msg.payload)[1]
                    tctx = TemplContext(
                        ts=resp_msgs[0][0],
                        path_params=params0,
                        body=flatten(req_sample),
                        placeholders=ctx.known,
                        request_prefix="req.payload",
                        siblings=sibling_values([_payload(m.payload)[1] for _, m, _ in resp_msgs]),
                    )
                    handler.response.payload_type = "json"
                    handler.response.payload = templatize(sample, tctx)
                else:
                    handler.response.payload_type = "text"
                    handler.response.payload = sample
        handlers.append(handler)
    ctx.summary.append(f"CoAP: {len(handlers)} resources" + (f", checksum {checksum.algorithm}" if checksum else ""))
    return frames, handlers


def _family_length_field(payloads: list[bytes], checksum: pm.Checksum | None) -> pm.LengthField | None:
    """A length field shared by all of a device's frame types (frames of several lengths disambiguate it)."""
    if len({len(p) for p in payloads}) < 2:
        return None
    width = fr.ALGORITHMS[checksum.algorithm][1] if checksum else 0
    return fr.find_length_field(payloads, width)


def _coap_payloads(
    ctx: _Ctx,
    channel: str,
    frame_id: str,
    msgs: list[tuple[float, CoapMessage, Ref]],
    direction: Direction,
    checksum: pm.Checksum | None,
    frames: list[pm.Frame],
    length_field: pm.LengthField | None = None,
) -> pm.Frame | None:
    binaries = [(ts, m.payload, ref) for ts, m, ref in msgs if m.payload and _payload(m.payload)[0] == "binary"]
    if not binaries:
        for ts, m, ref in msgs:
            kind, value = _payload(m.payload)
            if kind == "json":
                for p, v in flatten(value).items():
                    ctx.observe(channel, "payload." + p, direction, ts, v, ref)
        return None
    by_len: dict[int, list[tuple[float, bytes, Ref]]] = defaultdict(list)
    for item in binaries:
        by_len[len(item[1])].append(item)
    length, group = max(by_len.items(), key=lambda kv: len(kv[1]))
    fid = frame_id if len(by_len) == 1 else f"{frame_id}_{length}"
    layout, _ = fr.infer_frame(
        fid, [(ts, b) for ts, b, _ in group], _hints(ctx.annotations, direction), checksum, length_field
    )
    layout.evidence = _ev([ref for _, _, ref in group])
    frames.append(layout)
    for ts, b, ref in group:
        for fname, value in fr.decode_frame(b, layout).items():
            f = next(x for x in layout.fields if x.name == fname)
            if f.const is None:
                ctx.observe(channel, "fields." + fname, direction, ts, value, ref, name=fname)
    return layout


# ----------------------------------------------------------------------------- raw TCP/UDP


def _raw(ctx: _Ctx) -> tuple[list[pm.RawHandler], list[pm.Frame]]:
    if not ctx.sess.raw:
        return [], []
    by_port: dict[tuple[str, int], list[Any]] = defaultdict(list)
    for s in ctx.sess.raw:
        by_port[(s.transport, s.port)].append(s)
    handlers: list[pm.RawHandler] = []
    frames: list[pm.Frame] = []
    for (transport, port), streams in sorted(by_port.items()):
        hid = f"{transport}_{port}"
        if transport == "tcp":
            framing = fr.infer_framing([c[2] for s in streams for c in s.chunks])
            msgs: list[tuple[float, Direction, bytes, Ref]] = []
            for s in streams:
                for i, (ts, direction, data) in enumerate(s.chunks):
                    for j, f in enumerate(fr.split_frames(data, framing) or [data]):
                        msgs.append((ts + j * 1e-6, direction, f, Ref(s.capture, s.flow, i * 1000 + j)))
        else:
            framing = pm.Framing(kind="datagram")
            msgs = [
                (ts, direction, data, Ref(s.capture, s.flow, i))
                for s in streams
                for i, (ts, direction, data) in enumerate(s.chunks)
            ]
        msgs.sort(key=lambda m: m[0])
        checksum = fr.find_checksum([m[2] for m in msgs])
        length_field = _family_length_field([m[2] for m in msgs], checksum)
        handler = pm.RawHandler(
            id=hid,
            transport=cast(Any, transport),
            port=port,
            host=streams[0].host,
            framing=framing,
            evidence=_ev([m[3] for m in msgs]),
        )
        groups: dict[tuple[Direction, int], list[tuple[float, bytes, Ref]]] = defaultdict(list)
        for ts, direction, data, ref in msgs:
            groups[(direction, len(data))].append((ts, data, ref))
        layouts: dict[tuple[Direction, int], pm.Frame] = {}
        for (direction, length), group in sorted(groups.items(), key=lambda kv: (kv[0][0].value, kv[0][1])):
            fid = f"{hid}_{direction.value}_{length}"
            layout, _ = fr.infer_frame(
                fid, [(ts, b) for ts, b, _ in group], _hints(ctx.annotations, direction), checksum, length_field
            )
            layout.evidence = _ev([r for _, _, r in group])
            layouts[(direction, length)] = layout
            frames.append(layout)
            for ts, b, ref in group:
                for fname, value in fr.decode_frame(b, layout).items():
                    if next(x for x in layout.fields if x.name == fname).const is None:
                        ctx.observe(f"raw:{hid}:{fid}", "fields." + fname, direction, ts, value, ref, name=fname)
        for (direction, length), layout in layouts.items():
            if direction is not Direction.UP:
                continue
            rule = pm.RawRule(
                id=layout.id,
                frame=layout.id,
                match={f.name: f.const for f in layout.fields if f.const is not None},
                evidence=layout.evidence,
            )
            up_ts = [ts for ts, _, _ in groups[(direction, length)]]
            reply_counts: Counter[int] = Counter()
            for (d2, l2), g2 in groups.items():
                if d2 is Direction.DOWN:
                    for ts, _, _ in g2:
                        if any(0 <= ts - u <= 2.0 for u in up_ts):
                            reply_counts[l2] += 1
            if reply_counts:
                reply_len = reply_counts.most_common(1)[0][0]
                rule.reply = pm.FramePayload(frame=layouts[(Direction.DOWN, reply_len)].id)
            handler.rules.append(rule)
        handlers.append(handler)
        ctx.summary.append(
            f"Raw {transport}/{port}: framing {framing.kind}, {len(handler.rules)} message types"
            + (f", checksum {checksum.algorithm}" if checksum else "")
        )
    return handlers, frames


# ----------------------------------------------------------------------------- WebSocket

_WS_TYPE_KEYS = ("type", "cmd", "command", "action", "event", "op", "method", "msg")


def _websocket(ctx: _Ctx) -> list[pm.WebSocketHandler]:
    by_path: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for e in ctx.sess.ws:
        by_path[(e.host, e.path)].append(e)
    handlers: list[pm.WebSocketHandler] = []
    for (host, path), events in by_path.items():
        tm = infer_templates([path], "/", ctx.known)[path]
        hid = "ws_" + snake("_".join(_words(tm.template)) or "root")
        handler = pm.WebSocketHandler(
            id=hid,
            host=host,
            path=tm.template,
            identity=f"req.path.{next(iter(tm.params))}" if tm.params else None,
            evidence=_ev([e.ref for e in events]),
        )
        rules: dict[str, pm.WsMessageRule] = {}
        ups: dict[str, list[tuple[float, Any]]] = defaultdict(list)
        downs: list[tuple[float, Any, Ref]] = []
        for e in sorted(events, key=lambda x: x.ts):
            if e.msg.opcode not in (1, 2):
                continue
            kind, payload = _payload(e.msg.payload)
            if kind != "json" or not isinstance(payload, dict):
                continue
            tkey = next((k for k in _WS_TYPE_KEYS if isinstance(payload.get(k), str)), None)
            rid = snake(str(payload[tkey])) if tkey else "message"
            if e.dir is Direction.UP:
                if rid not in rules:
                    rules[rid] = pm.WsMessageRule(id=rid, match={tkey: payload[tkey]} if tkey else {})
                rules[rid].evidence = (rules[rid].evidence + _ev([e.ref]))[:5]
                ups[rid].append((e.ts, payload))
                for p, v in flatten(payload).items():
                    if p != tkey:
                        ctx.observe(f"ws:{hid}:{rid}", "payload." + p, Direction.UP, e.ts, v, e.ref)
            else:
                downs.append((e.ts, payload, e.ref))
                for p, v in flatten(payload).items():
                    ctx.observe(f"ws:{hid}:down", "payload." + p, Direction.DOWN, e.ts, v, e.ref)
        for rid, rule in rules.items():
            replies = [next((p for dts, p, _ in downs if 0 <= dts - uts <= 1.0), None) for uts, _ in ups[rid]]
            if replies and all(r is not None for r in replies):
                last_up = ups[rid][0][1]
                tctx = TemplContext(
                    ts=ups[rid][0][0],
                    body=flatten(last_up),
                    placeholders=ctx.known,
                    siblings=sibling_values(replies),
                    request_prefix="req.payload",
                )
                rule.reply = templatize(replies[0], tctx)
        handler.messages = list(rules.values())
        handlers.append(handler)
    return handlers


# ----------------------------------------------------------------------------- state & commands

_UNIT_HINTS = (
    (("temp", "temperature", "setpoint", "target"), "°C"),
    (("humidity", "hum", "rh"), "%"),
    (("battery", "batt"), "%"),
    (("watts", "watt", "power_w"), "W"),
    (("energy", "kwh"), "kWh"),
    (("voltage", "volt"), "V"),
)


def _unit_for(name: str, given: str | None) -> str | None:
    if given:
        return given
    parts = set(name.split("_"))
    for words, unit in _UNIT_HINTS:
        if parts & set(words) or name in words:
            return unit
    return None


def _source_expr(series: FieldSeries) -> str:
    return "req." + series.path


def _apply_state(
    ctx: _Ctx,
    profile: pm.Profile,
    variables: list[VariableEvidence],
    http: list[pm.HttpHandler],
    groups: list[_HttpGroup],
    mqtt: pm.MqttConfig | None,
    coap: list[pm.CoapHandler],
    raw: list[pm.RawHandler],
    ws: list[pm.WebSocketHandler],
) -> None:
    http_by_id = {h.id: h for h in http}
    group_by_id = {g.id: g for g in groups}
    topics = {t.id: t for t in (mqtt.topics if mqtt else [])}
    coap_by_id = {h.id: h for h in coap}
    for var in variables:
        observed: list[Scalar] = []
        if var.report:
            scale = var.report_match.scale if var.report_match else None
            for v in var.report.values:
                if isinstance(v, int | float) and not isinstance(v, bool) and scale:
                    observed.append(round(v * scale, 6))
                elif var.report_match and var.report_match.value_map and json.dumps(v) in var.report_match.value_map:
                    observed.append(var.report_match.value_map[json.dumps(v)])
                else:
                    observed.append(v)
        allv = [v for v in observed + var.annotated_values if v is not None]
        vtype: str
        if var.kind == "bool" or (allv and all(isinstance(v, bool) for v in allv)):
            vtype = "bool"
        elif allv and all(isinstance(v, int | float) and not isinstance(v, bool) for v in allv):
            vtype = (
                "int"
                if all(isinstance(v, int) or float(v).is_integer() for v in allv)
                and not (var.report_match and var.report_match.scale)
                else "float"
            )
        elif var.kind in ("enum", "string"):
            vtype = "enum" if len({str(v) for v in allv}) <= 8 else "string"
        else:
            vtype = "string"
        sv = pm.StateVariable(
            name=var.name,
            type=cast(Any, vtype),
            writable=var.writable,
            unit=_unit_for(var.name, var.unit),
            evidence=_ev(var.refs),
            description=f"inferred by {var.confidence} rule",
        )
        if vtype == "enum":
            sv.options = list[Any](sorted({str(v) for v in allv}))
        if vtype in ("int", "float") and allv:
            nums = [float(v) for v in allv if isinstance(v, int | float) and not isinstance(v, bool)]
            lo, hi = min(nums), max(nums)
            if var.writable and sv.unit == "°C":
                lo, hi, sv.step = min(lo, 5.0), max(hi, 35.0), 0.5
            elif var.writable:
                sv.step = 1.0 if vtype == "int" else 0.1
            sv.min, sv.max = round(lo, 6), round(hi, 6)
        profile.state.append(sv)
        if var.report:
            ex = pm.Extract(
                source=_source_expr(var.report),
                variable=var.name,
                scale=var.report_match.scale if var.report_match else None,
                value_map=dict(var.report_match.value_map) if var.report_match and var.report_match.value_map else None,
            )
            _attach_extract(var.report.channel, ex, http_by_id, topics, coap_by_id, raw, ws)
        if var.command and var.writable:
            cmd = _command(ctx, var, http_by_id, group_by_id, topics, coap_by_id, raw, ws)
            if cmd is not None:
                profile.commands.append(cmd)


def _attach_extract(
    channel: str,
    ex: pm.Extract,
    http: dict[str, pm.HttpHandler],
    topics: dict[str, pm.MqttTopic],
    coap: dict[str, pm.CoapHandler],
    raw: list[pm.RawHandler],
    ws: list[pm.WebSocketHandler],
) -> None:
    kind, hid, *rest = channel.split(":")
    if kind == "http" and hid in http:
        http[hid].extract.append(ex)
    elif kind == "mqtt" and hid in topics:
        topics[hid].extract.append(ex)
    elif kind == "coap" and hid in coap:
        coap[hid].extract.append(ex)
    elif kind == "raw":
        for h in raw:
            for r in h.rules:
                if h.id == hid and r.frame == rest[0]:
                    r.extract.append(ex)
    elif kind == "ws":
        for w in ws:
            for m in w.messages:
                if w.id == hid and m.id == rest[0]:
                    m.extract.append(ex)


def _invert(vm: dict[str, Scalar] | None) -> dict[str, Any] | None:
    if not vm:
        return None
    out: dict[str, Any] = {}
    for device_json, state in vm.items():
        out[json.dumps(state)] = json.loads(device_json)
    return out


def _command(
    ctx: _Ctx,
    var: VariableEvidence,
    http: dict[str, pm.HttpHandler],
    groups: dict[str, _HttpGroup],
    topics: dict[str, pm.MqttTopic],
    coap: dict[str, pm.CoapHandler],
    raw: list[pm.RawHandler],
    ws: list[pm.WebSocketHandler],
) -> pm.Command | None:
    assert var.command is not None
    series = var.command
    kind, hid, *_ = series.channel.split(":")
    vm = _invert(var.command_match.value_map if var.command_match else None)
    scale = var.command_match.scale if var.command_match else None
    evidence = _ev([o.ref for o in series.obs[:3]])
    name = f"set_{var.name}"
    leaf_path = series.path.split(".", 1)[1] if "." in series.path else series.path
    if kind == "http" and hid in http:
        handler, group = http[hid], groups[hid]
        segs = leaf_path.split(".")
        list_idx = next((i for i, s in enumerate(segs) if s.isdigit()), None)
        bodies = [parse_body(ex.resp.header("content-type"), ex.resp.body) for ex, _ in group.exchanges if ex.resp]
        with_cmd = [b for b in bodies if get_path(b, leaf_path) is not None]
        if not with_cmd:
            return None
        if list_idx is not None:
            container = ".".join(segs[:list_idx])
            item_path = ".".join(segs[: list_idx + 1])
            inner = ".".join(segs[list_idx + 1 :])
            delivery = pm.CommandDelivery(mode="list", path=container)
        else:
            container = ".".join(segs[:-1])
            item_path, inner = container, segs[-1]
            delivery = pm.CommandDelivery(mode="replace", path=container)
        items = [get_path(b, item_path) for b in with_cmd]
        item = items[0]
        tctx = TemplContext(ts=series.obs[0].ts, siblings=sibling_values(items), placeholders=ctx.known)
        templ = templatize(item, tctx)
        templ = _set_leaf(templ, inner, "{{cmd.value}}")
        handler.delivers_commands = delivery
        idle = [b for b in bodies if not get_path(b, container)] if container else []
        if idle:
            base = handler.response.body
            idle_t = templatize(idle[0], TemplContext(ts=series.obs[0].ts, placeholders=ctx.known))
            handler.response.body = idle_t if isinstance(base, dict) else base
        return pm.Command(
            name=name,
            variable=var.name,
            transport="http_poll",
            handler=hid,
            template=templ,
            value_map=vm,
            scale=scale,
            evidence=evidence,
        )
    if kind == "mqtt" and hid in topics:
        topic = topics[hid]
        pubs = _mqtt_payloads(ctx, hid)
        sample = next((p for p in pubs if get_path(p, leaf_path) is not None), None)
        if sample is None:
            return None
        tctx = TemplContext(ts=series.obs[0].ts, siblings=sibling_values(pubs), placeholders=ctx.known)
        templ = _set_leaf(templatize(sample, tctx), leaf_path, "{{cmd.value}}")
        return pm.Command(
            name=name,
            variable=var.name,
            transport="mqtt",
            handler=topic.id,
            template=templ,
            value_map=vm,
            scale=scale,
            evidence=evidence,
        )
    if kind == "coap" and hid in coap:
        h = coap[hid]
        expr = "{{desired." + var.name + "}}"
        if h.response.frame is not None:
            fname = series.name or leaf_path
            h.response.frame.values[fname] = expr
        elif h.response.payload_type == "json":
            h.response.payload = _set_leaf(h.response.payload, leaf_path, expr)
        return pm.Command(
            name=name,
            variable=var.name,
            transport="coap_response",
            handler=hid,
            value_map=vm,
            scale=scale,
            evidence=evidence,
        )
    if kind == "raw":
        for rh in raw:
            if rh.id != hid:
                continue
            for rule in rh.rules:
                if rule.reply is not None and series.channel.endswith(":" + rule.reply.frame):
                    rule.reply.values[series.name or leaf_path] = "{{desired." + var.name + "}}"
            return pm.Command(
                name=name, variable=var.name, transport="raw", handler=hid, value_map=vm, scale=scale, evidence=evidence
            )
    if kind == "ws":
        downs = [e for e in ctx.sess.ws if e.dir is Direction.DOWN]
        for e in downs:
            k, p = _payload(e.msg.payload)
            if k == "json" and get_path(p, leaf_path) is not None:
                templ = _set_leaf(
                    templatize(p, TemplContext(ts=e.ts, placeholders=ctx.known)), leaf_path, "{{cmd.value}}"
                )
                return pm.Command(
                    name=name,
                    variable=var.name,
                    transport="websocket",
                    handler=hid,
                    template=templ,
                    value_map=vm,
                    scale=scale,
                    evidence=evidence,
                )
    return None


def _mqtt_payloads(ctx: _Ctx, topic_id: str) -> list[Any]:
    out = []
    for (channel, _), s in ctx.series.items():
        if channel == f"mqtt:{topic_id}":
            out.append(s)
    # Re-read full payloads from sessions to keep sibling fields intact.
    result: list[Any] = []
    for sess in ctx.sess.mqtt:
        for e in sess.events:
            if e.packet.type == "PUBLISH" and e.dir is Direction.DOWN:
                kind, p = _payload(e.packet.payload)
                if kind == "json" and any(o.ref == e.ref for s in out for o in s.obs):
                    result.append(p)
    return result


def _set_leaf(template: Any, path: str, value: Any) -> Any:
    if path == "":
        return value
    if get_path(template, path) is None and not isinstance(template, dict | list):
        return template
    segs = path.split(".")
    cur = template
    for s in segs[:-1]:
        cur = cur[int(s)] if isinstance(cur, list) else cur.get(s) if isinstance(cur, dict) else None
        if cur is None:
            return template
    if isinstance(cur, list):
        cur[int(segs[-1])] = value
    elif isinstance(cur, dict):
        cur[segs[-1]] = value
    return template


# ----------------------------------------------------------------------------- Home Assistant


def _home_assistant(profile: pm.Profile) -> pm.HomeAssistant:
    entities: list[pm.HaEntity] = []
    used: set[str] = set()
    state = profile.state
    target = next((v for v in state if v.writable and v.type in ("int", "float") and v.unit == "°C"), None)
    current = next((v for v in state if not v.writable and v.type in ("int", "float") and v.unit == "°C"), None)
    mode = next((v for v in state if v.writable and v.type == "enum" and "mode" in v.name), None)
    if target and (current or mode):
        mode_map = {}
        if mode:
            for opt in mode.options:
                ha = _HA_MODES.get(str(opt).lower())
                if ha:
                    mode_map[str(opt)] = ha
        action = next(
            (
                v
                for v in state
                if not v.writable and v.type == "bool" and v.name in ("heating", "cooling", "running", "active")
            ),
            None,
        )
        entities.append(
            pm.HaEntity(
                platform="climate",
                key="climate",
                name=profile.name,
                current_temperature=current.name if current else None,
                target_temperature=target.name,
                hvac_mode=mode.name if mode and mode_map else None,
                hvac_mode_map=mode_map,
                hvac_action=action.name if action else None,
                unit="°C",
                min=target.min,
                max=target.max,
                step=target.step,
            )
        )
        used.add(target.name)
        if mode and mode_map:
            used.add(mode.name)
    for v in state:
        if v.name in used:
            continue
        title = v.name.replace("_", " ").capitalize()
        if v.type == "bool":
            if v.writable:
                platform = "light" if any(w in v.name for w in ("light", "lamp", "bulb")) else "switch"
                entities.append(pm.HaEntity(platform=cast(Any, platform), key=v.name, name=title, variable=v.name))
            else:
                dc = "heat" if v.name in ("heating",) else ("power" if v.name in ("power", "on") else None)
                entities.append(
                    pm.HaEntity(platform="binary_sensor", key=v.name, name=title, variable=v.name, device_class=dc)
                )
        elif v.type in ("int", "float"):
            if v.writable:
                entities.append(
                    pm.HaEntity(
                        platform="number",
                        key=v.name,
                        name=title,
                        variable=v.name,
                        unit=v.unit,
                        min=v.min,
                        max=v.max,
                        step=v.step,
                    )
                )
            else:
                dc = {"°C": "temperature", "W": "power", "kWh": "energy", "V": "voltage"}.get(v.unit or "")
                if v.unit == "%":
                    dc = "battery" if "batt" in v.name else ("humidity" if "hum" in v.name else None)
                entities.append(
                    pm.HaEntity(
                        platform="sensor",
                        key=v.name,
                        name=title,
                        variable=v.name,
                        unit=v.unit,
                        device_class=dc,
                        state_class="measurement",
                    )
                )
        elif v.type == "enum":
            if v.writable:
                entities.append(
                    pm.HaEntity(
                        platform="select", key=v.name, name=title, variable=v.name, options=[str(o) for o in v.options]
                    )
                )
            else:
                entities.append(
                    pm.HaEntity(
                        platform="sensor",
                        key=v.name,
                        name=title,
                        variable=v.name,
                        device_class="enum",
                        options=[str(o) for o in v.options],
                    )
                )
    return pm.HomeAssistant(entities=entities)


def _regex_from_template(template: str) -> str:
    parts = re.split(r"(\{[^}]+\})", template)
    return "^" + "".join(".+" if p.startswith("{") and p.endswith("}") else re.escape(p) for p in parts) + "$"


def _placeholder_kind(name: str, value: str) -> str:
    low = name.lower()
    if is_mac(value) or "mac" in low:
        return "mac"
    if "serial" in low or low == "sn":
        return "serial"
    if "user" in low or "account" in low or "@" in value:
        return "account"
    return "device_id"
