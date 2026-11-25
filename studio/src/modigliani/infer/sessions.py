"""Session reconstruction: turn capture flows into decoded, timestamped protocol events.

Every event keeps (capture, flow, message index) so that each inferred profile element
can cite the exact traffic it came from.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from modigliani.capture.model import Capture, Direction, Flow, TlsOutcome
from modigliani.infer import decoders as d


@dataclass(frozen=True)
class Ref:
    capture: str
    flow: int
    message: int


@dataclass
class HttpExchange:
    ref: Ref
    host: str
    port: int
    tls: bool
    req: d.HttpRequest
    resp: d.HttpResponse | None
    ts: float
    resp_ts: float | None


@dataclass
class MqttEvent:
    ref: Ref
    ts: float
    dir: Direction
    packet: d.MqttPacket


@dataclass
class MqttSession:
    capture: str
    flow: int
    host: str
    port: int
    tls: bool
    level: int
    connect: d.MqttPacket | None
    events: list[MqttEvent] = field(default_factory=list)


@dataclass
class CoapEvent:
    ref: Ref
    ts: float
    dir: Direction
    host: str
    port: int
    msg: d.CoapMessage


@dataclass
class WsEvent:
    ref: Ref
    ts: float
    dir: Direction
    host: str
    path: str
    msg: d.WsMessage


@dataclass
class RawStream:
    capture: str
    flow: int
    transport: str
    host: str
    port: int
    # For TCP: one entry per direction holding the whole stream. For UDP: one per datagram.
    chunks: list[tuple[float, Direction, bytes]] = field(default_factory=list)


@dataclass
class TlsObservation:
    capture: str
    flow: int
    host: str
    port: int
    outcome: TlsOutcome
    detail: str
    start: float
    end: float
    bytes_up: int
    bytes_down: int
    messages: int


@dataclass
class DeviceSessions:
    device: str
    http: list[HttpExchange] = field(default_factory=list)
    mqtt: list[MqttSession] = field(default_factory=list)
    coap: list[CoapEvent] = field(default_factory=list)
    ws: list[WsEvent] = field(default_factory=list)
    raw: list[RawStream] = field(default_factory=list)
    tls: list[TlsObservation] = field(default_factory=list)
    dns_names: set[str] = field(default_factory=set)
    start: float = 0.0
    end: float = 0.0


def _ts_at(marks: list[tuple[int, float]], offset: int) -> float:
    if not marks:
        return 0.0
    offsets = [m[0] for m in marks]
    i = bisect.bisect_right(offsets, offset) - 1
    return marks[max(i, 0)][1]


def _host(flow: Flow) -> str:
    return flow.hostname or flow.tls.sni or flow.server.host


class _Indexer:
    """Assigns message indices in time order across both directions of a flow."""

    def __init__(self) -> None:
        self.items: list[tuple[float, int, object]] = []

    def add(self, ts: float, obj: object) -> None:
        self.items.append((ts, len(self.items), obj))

    def ordered(self) -> list[tuple[int, object]]:
        return [(i, obj) for i, (_, _, obj) in enumerate(sorted(self.items, key=lambda t: (t[0], t[1])))]


def build_sessions(captures: list[Capture], device: str | None = None) -> DeviceSessions:
    name = device or (captures[0].devices[0].name if captures and captures[0].devices else "device")
    out = DeviceSessions(device=name)
    times: list[float] = []
    for cap in captures:
        for rec in cap.dns:
            if device is None or rec.device == device:
                out.dns_names.add(rec.qname.rstrip(".").lower())
        for flow in cap.flows_for(device):
            if flow.segments:
                times += [flow.start, flow.end]
            _decode_flow(cap.name, flow, out)
    if times:
        out.start, out.end = min(times), max(times)
    return out


def _tls_observation(cap: str, flow: Flow, outcome: TlsOutcome) -> TlsObservation:
    up = sum(s.size for s in flow.segments if s.dir is Direction.UP)
    down = sum(s.size for s in flow.segments if s.dir is Direction.DOWN)
    return TlsObservation(
        capture=cap,
        flow=flow.index,
        host=_host(flow),
        port=flow.server.port,
        outcome=outcome,
        detail=flow.tls.detail,
        start=flow.start,
        end=flow.end,
        bytes_up=up,
        bytes_down=down,
        messages=len(flow.segments),
    )


def _decode_flow(cap: str, flow: Flow, out: DeviceSessions) -> None:
    outcome = flow.tls.outcome
    if outcome in (TlsOutcome.REJECTED_LOCAL_CA, TlsOutcome.PASSTHROUGH, TlsOutcome.UNTESTED):
        out.tls.append(_tls_observation(cap, flow, outcome))
        return
    if flow.metadata_only:
        out.tls.append(_tls_observation(cap, flow, TlsOutcome.UNTESTED))
        return
    up, up_marks = flow.stream(Direction.UP)
    down, down_marks = flow.stream(Direction.DOWN)
    is_tls = outcome is TlsOutcome.ACCEPTED_LOCAL_CA
    if flow.transport == "tcp" and d.looks_like_tls(up) and outcome is TlsOutcome.PLAINTEXT:
        # A passive capture of an encrypted session: we keep metadata only.
        flow.tls.sni = flow.tls.sni or d.tls_client_hello_sni(up)
        out.tls.append(_tls_observation(cap, flow, TlsOutcome.UNTESTED))
        return
    host, port = _host(flow), flow.server.port
    if flow.transport == "udp":
        datagrams = [(s.ts, s.dir, s.payload()) for s in flow.segments if s.data is not None]
        if datagrams and all(d.looks_like_coap(p) for _, _, p in datagrams):
            for i, (ts, direction, payload) in enumerate(datagrams):
                msg = d.decode_coap(payload)
                out.coap.append(CoapEvent(Ref(cap, flow.index, i), ts, direction, host, port, msg))
        else:
            out.raw.append(RawStream(cap, flow.index, "udp", host, port, datagrams))
        return

    if up.startswith(d.HTTP_METHODS):
        _decode_http(cap, flow, out, up, up_marks, down, down_marks, host, port, is_tls)
    elif d.looks_like_mqtt_connect(up):
        _decode_mqtt(cap, flow, out, up, up_marks, down, down_marks, host, port, is_tls)
    else:
        chunks: list[tuple[float, Direction, bytes]] = []
        if up:
            chunks.append((up_marks[0][1], Direction.UP, up))
        if down:
            chunks.append((down_marks[0][1], Direction.DOWN, down))
        out.raw.append(RawStream(cap, flow.index, "tcp", host, port, chunks))


def _decode_http(
    cap: str,
    flow: Flow,
    out: DeviceSessions,
    up: bytes,
    up_marks: list[tuple[int, float]],
    down: bytes,
    down_marks: list[tuple[int, float]],
    host: str,
    port: int,
    is_tls: bool,
) -> None:
    reqs = d.decode_http_requests(up)
    resps = d.decode_http_responses(down, [r.method for r in reqs])
    idx = _Indexer()
    pairs: list[tuple[d.HttpRequest, d.HttpResponse | None]] = []
    for i, req in enumerate(reqs):
        resp = resps[i] if i < len(resps) else None
        pairs.append((req, resp))
        idx.add(_ts_at(up_marks, req.offset), ("req", i))
        if resp is not None:
            idx.add(_ts_at(down_marks, resp.offset), ("resp", i))
    numbering: dict[tuple[str, int], int] = {}
    for n, obj in idx.ordered():
        assert isinstance(obj, tuple)
        numbering[(obj[0], obj[1])] = n
    req_host = host
    for i, (req, resp) in enumerate(pairs):
        h = (req.header("host") or req_host).split(":")[0] if not flow.hostname else req_host
        out.http.append(
            HttpExchange(
                ref=Ref(cap, flow.index, numbering[("req", i)]),
                host=h,
                port=port,
                tls=is_tls,
                req=req,
                resp=resp,
                ts=_ts_at(up_marks, req.offset),
                resp_ts=_ts_at(down_marks, resp.offset) if resp else None,
            )
        )
    # WebSocket upgrade: everything after the 101 response is frames.
    if reqs and resps and resps[-1].status == 101 and d.is_ws_upgrade(reqs[-1].headers):
        path = reqs[-1].path
        base = len(numbering)
        events: list[tuple[float, Direction, d.WsMessage]] = []
        for m in d.decode_ws_frames(up[reqs[-1].end :]):
            events.append((_ts_at(up_marks, reqs[-1].end + m.offset), Direction.UP, m))
        for m in d.decode_ws_frames(down[resps[-1].end :]):
            events.append((_ts_at(down_marks, resps[-1].end + m.offset), Direction.DOWN, m))
        events.sort(key=lambda e: e[0])
        for j, (ts, direction, m) in enumerate(events):
            out.ws.append(WsEvent(Ref(cap, flow.index, base + j), ts, direction, host, path, m))


def _decode_mqtt(
    cap: str,
    flow: Flow,
    out: DeviceSessions,
    up: bytes,
    up_marks: list[tuple[int, float]],
    down: bytes,
    down_marks: list[tuple[int, float]],
    host: str,
    port: int,
    is_tls: bool,
) -> None:
    up_pk, level = d.decode_mqtt(up)
    down_pk, _ = d.decode_mqtt(down, level)
    idx = _Indexer()
    for p in up_pk:
        idx.add(_ts_at(up_marks, p.offset), (Direction.UP, p))
    for p in down_pk:
        idx.add(_ts_at(down_marks, p.offset), (Direction.DOWN, p))
    connect = next((p for p in up_pk if p.type == "CONNECT"), None)
    session = MqttSession(cap, flow.index, host, port, is_tls, level, connect)
    for n, obj in idx.ordered():
        assert isinstance(obj, tuple)
        direction, pk = obj
        marks = up_marks if direction is Direction.UP else down_marks
        session.events.append(MqttEvent(Ref(cap, flow.index, n), _ts_at(marks, pk.offset), direction, pk))
    out.mqtt.append(session)
