"""Proxy-mode recording with mitmproxy used as a library.

Each route listens on a local port and forwards the device's own traffic to the real vendor
server (reverse-proxy mode). TLS is terminated with a certificate from the local CA. When a
device refuses that certificate it strictly verifies the vendor's certificate: the attempt is
recorded as `rejected_local_ca`, and later connections from that device to that host are
passed through untouched with metadata only. Modigliani never retries with tricks to get
around verification.

Only enrolled devices are served; connections from anyone else are closed and not stored.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from modigliani import ca
from modigliani.capture.enrollment import Enrollment, visible_devices
from modigliani.capture.model import (
    Capture,
    DeviceRef,
    Direction,
    Endpoint,
    Flow,
    Segment,
    TlsInfo,
    TlsOutcome,
)
from modigliani.infer.decoders import encode_ws_frame, tls_client_hello_sni

Scheme = Literal["https", "http", "tls", "tcp", "udp"]
_ROUTE_RE = re.compile(
    r"^(?P<scheme>https|http|tls|tcp|udp):(?:(?P<lhost>[\d.]+|\[[0-9a-f:]+\]):)?(?P<lport>\d+)"
    r"=(?P<hostname>[^@\s]+)(?:@(?P<uhost>[^:\s]+):(?P<uport>\d+))?$"
)
_DEFAULT_PORTS = {"https": 443, "http": 80, "tls": 8883, "tcp": 80, "udp": 5683}


class ProxyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Route:
    scheme: Scheme
    listen_port: int
    hostname: str
    upstream_host: str
    upstream_port: int
    listen_host: str = "0.0.0.0"

    @classmethod
    def parse(cls, spec: str) -> Route:
        """`SCHEME:[LISTEN_HOST:]LISTEN_PORT=HOSTNAME[@UPSTREAM_HOST:UPSTREAM_PORT]`.

        Example (localhost port mapping): `https:18443=api.vendor.example@127.0.0.1:28443`.
        Without an upstream, Modigliani connects to HOSTNAME on the scheme's default port.
        """
        m = _ROUTE_RE.match(spec.strip())
        if not m:
            raise ProxyError(f"bad route {spec!r}; expected SCHEME:PORT=HOSTNAME[@UPSTREAM:PORT]")
        scheme: Any = m.group("scheme")
        return cls(
            scheme=scheme,
            listen_port=int(m.group("lport")),
            hostname=m.group("hostname"),
            upstream_host=m.group("uhost") or m.group("hostname"),
            upstream_port=int(m.group("uport") or _DEFAULT_PORTS[scheme]),
            listen_host=(m.group("lhost") or "0.0.0.0").strip("[]"),
        )

    @property
    def wildcard(self) -> bool:
        """`*` routes forward each connection to the host the device names (SNI or Host header)."""
        return self.hostname == "*"

    def mode(self) -> str:
        # Wildcard routes get a placeholder target that server_connect rewrites per connection.
        upstream = "127.0.0.1" if self.wildcard else self.upstream_host
        return f"reverse:{self.scheme}://{upstream}:{self.upstream_port}@{self.listen_host}:{self.listen_port}"


@dataclass
class _FlowBuilder:
    flow: Flow
    ws_started: bool = False


@dataclass
class Recorder:
    """mitmproxy addon that turns proxied traffic into a Modigliani capture."""

    enrollment: Enrollment
    routes: list[Route]
    name: str
    flows: dict[str, _FlowBuilder] = field(default_factory=dict)
    rejecting: set[tuple[str, str]] = field(default_factory=set)
    devices: dict[str, DeviceRef] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    arp_cache: dict[str, str] = field(default_factory=dict)
    counter: int = 0
    # Maps a vendor hostname to its real address (router-mode DNS knows it); None: system DNS.
    resolver: Callable[[str], str | None] | None = None

    # ------------------------------------------------------------------ helpers

    def _route_for(self, sockname: Any) -> Route | None:
        port = sockname[1] if sockname else None
        return next((r for r in self.routes if r.listen_port == port), None)

    def _mac_for(self, ip: str) -> str | None:
        if ip in ("127.0.0.1", "::1"):
            return None
        if ip not in self.arp_cache:
            for n in visible_devices():
                self.arp_cache[n.ip] = n.mac
        return self.arp_cache.get(ip)

    def _device(self, client: Any) -> str | None:
        ip = client.peername[0] if client.peername else ""
        dev = self.enrollment.match(ip=ip, mac=self._mac_for(ip))
        if dev is None:
            return None
        self.devices.setdefault(dev.name, DeviceRef(name=dev.name, mac=dev.mac, ip=ip))
        return dev.name

    def _builder(self, client: Any, transport: str = "tcp") -> _FlowBuilder | None:
        with self.lock:
            fb = self.flows.get(client.id)
            if fb is not None:
                return fb
            device = self._device(client)
            route = self._route_for(client.sockname)
            if device is None or route is None:
                return None
            fb = _FlowBuilder(
                Flow(
                    index=self.counter,
                    device=device,
                    transport=cast(Any, transport),
                    client=Endpoint(host=client.peername[0], port=client.peername[1]),
                    server=Endpoint(host=route.upstream_host, port=route.upstream_port),
                    hostname=route.hostname if route.hostname != "*" else None,
                    tls=TlsInfo(outcome=TlsOutcome.PLAINTEXT),
                )
            )
            self.counter += 1
            self.flows[client.id] = fb
            return fb

    def _add(self, fb: _FlowBuilder, ts: float, direction: Direction, data: bytes) -> None:
        with self.lock:
            if fb.flow.metadata_only:
                fb.flow.segments.append(Segment.metadata(ts, direction, len(data)))
            else:
                fb.flow.segments.append(Segment.from_bytes(ts, direction, data))

    # ------------------------------------------------------------------ mitmproxy hooks

    def client_connected(self, client: Any) -> None:
        if self._device(client) is None:
            # Not an enrolled device: refuse the connection and keep nothing.
            client.error = "not an enrolled device"

    def next_layer(self, nextlayer: Any) -> None:
        """Pass previously rejected device/host pairs through as opaque TCP.

        mitmproxy's default addon has already chosen a TLS layer by the time this hook runs;
        replacing it with a plain TCP layer (not mitmproxy's "ignored" mode) forwards the bytes
        untouched while still emitting tcp_message events, so timing and sizes are recorded and
        the ciphertext itself is discarded.
        """
        from mitmproxy.proxy.layers import ClientTLSLayer, ServerTLSLayer, TCPLayer

        if not isinstance(nextlayer.layer, ClientTLSLayer | ServerTLSLayer):
            return
        client = nextlayer.context.client
        hello = nextlayer.data_client()
        if client.transport_protocol != "tcp" or not hello.startswith(b""):
            return
        fb = self._builder(client)
        if fb is None:
            return
        sni = tls_client_hello_sni(hello) or fb.flow.hostname or ""
        if (client.peername[0], sni) in self.rejecting:
            nextlayer.context.server.tls = False
            nextlayer.layer = TCPLayer(nextlayer.context)
            fb.flow.metadata_only = True
            fb.flow.tls = TlsInfo(
                outcome=TlsOutcome.PASSTHROUGH,
                sni=sni or None,
                detail="device rejected the local CA earlier; forwarded untouched",
            )

    def tls_clienthello(self, data: Any) -> None:
        fb = self._builder(data.context.client)
        if fb is None:
            return
        sni = data.client_hello.sni or fb.flow.hostname or ""
        fb.flow.tls.sni = sni or None
        if sni and fb.flow.hostname is None:
            fb.flow.hostname = sni

    def tls_established_client(self, data: Any) -> None:
        fb = self._builder(data.context.client)
        if fb is not None:
            fb.flow.tls.outcome = TlsOutcome.ACCEPTED_LOCAL_CA

    def tls_failed_client(self, data: Any) -> None:
        client = data.context.client
        fb = self._builder(client)
        if fb is None:
            return
        sni = fb.flow.tls.sni or fb.flow.hostname or ""
        self.rejecting.add((client.peername[0], sni))
        fb.flow.metadata_only = True
        fb.flow.tls = TlsInfo(
            outcome=TlsOutcome.REJECTED_LOCAL_CA,
            sni=sni or None,
            detail=str(getattr(data.conn, "error", "") or "handshake aborted by device"),
        )
        fb.flow.segments.append(Segment.metadata(time.time(), Direction.UP, 0))

    def _upstream_for(self, name: str) -> str:
        real = self.resolver(name) if self.resolver else None
        return real or name

    def server_connect(self, data: Any) -> None:
        route = self._route_for(data.client.sockname)
        if route is None or not route.wildcard:
            return
        name = data.client.sni
        if not name:
            if route.scheme in ("https", "tls"):
                data.server.error = "wildcard TLS route needs SNI to know the vendor host"
            return
        data.server.address = (self._upstream_for(name), route.upstream_port)
        data.server.sni = name

    def requestheaders(self, flow: Any) -> None:
        route = self._route_for(flow.client_conn.sockname)
        if route is not None and route.wildcard and route.scheme == "http":
            host = flow.request.host_header
            if host:
                flow.request.host = self._upstream_for(host.split(":")[0])
                flow.request.port = route.upstream_port

    def response(self, flow: Any) -> None:
        from mitmproxy.net.http.http1.assemble import assemble_request, assemble_response

        fb = self._builder(flow.client_conn)
        if fb is None:
            return
        if fb.flow.hostname is None:
            fb.flow.hostname = flow.request.host_header or flow.request.pretty_host
        try:
            req_bytes = assemble_request(flow.request)
            resp_bytes = assemble_response(flow.response)
        except ValueError:
            return
        self._add(fb, flow.request.timestamp_start or time.time(), Direction.UP, req_bytes)
        self._add(fb, flow.response.timestamp_start or time.time(), Direction.DOWN, resp_bytes)

    def websocket_message(self, flow: Any) -> None:
        fb = self._builder(flow.client_conn)
        if fb is None or flow.websocket is None:
            return
        msg = flow.websocket.messages[-1]
        opcode = int(msg.type)
        if msg.from_client:
            self._add(fb, msg.timestamp, Direction.UP, encode_ws_frame(opcode, msg.content, mask=b"\x00\x00\x00\x00"))
        else:
            self._add(fb, msg.timestamp, Direction.DOWN, encode_ws_frame(opcode, msg.content))

    def tcp_message(self, flow: Any) -> None:
        fb = self._builder(flow.client_conn)
        if fb is None:
            return
        msg = flow.messages[-1]
        self._add(fb, msg.timestamp, Direction.UP if msg.from_client else Direction.DOWN, msg.content)

    def udp_message(self, flow: Any) -> None:
        fb = self._builder(flow.client_conn, transport="udp")
        if fb is None:
            return
        fb.flow.transport = "udp"
        msg = flow.messages[-1]
        self._add(fb, msg.timestamp, Direction.UP if msg.from_client else Direction.DOWN, msg.content)

    # ------------------------------------------------------------------ output

    def capture(self) -> Capture:
        with self.lock:
            flows = [fb.flow for fb in self.flows.values() if fb.flow.segments]
        flows.sort(key=lambda f: f.start)
        for i, f in enumerate(flows):
            f.index = i
            f.segments.sort(key=lambda s: s.ts)
        return Capture(
            name=self.name, created=time.time(), mode="proxy", devices=list(self.devices.values()), flows=flows
        )


async def run_proxy(
    recorder: Recorder,
    ca_dir: Path,
    *,
    seconds: float,
    upstream_ca: Path | None = None,
    stop: threading.Event | None = None,
    ready: threading.Event | None = None,
) -> Capture:
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    if not recorder.routes:
        raise ProxyError("proxy mode needs at least one --route")
    confdir = Path(tempfile.mkdtemp(prefix="modigliani-proxy-"))
    try:
        ca.write_mitmproxy_confdir(ca_dir, confdir)
        opts = Options(confdir=str(confdir))
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        master.addons.add(recorder)
        master.options.update(
            mode=[r.mode() for r in recorder.routes],
            keep_host_header=True,
            connection_strategy="lazy",
            ssl_verify_upstream_trusted_ca=str(upstream_ca) if upstream_ca else None,
        )
        task = asyncio.create_task(master.run())
        await asyncio.sleep(0.5)
        if task.done():
            task.result()
        if ready is not None:
            ready.set()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not (stop and stop.is_set()) and not task.done():
            await asyncio.sleep(0.2)
        master.shutdown()
        try:
            await asyncio.wait_for(task, timeout=10)
        except TimeoutError:
            task.cancel()
    finally:
        shutil.rmtree(confdir, ignore_errors=True)
    return recorder.capture()
