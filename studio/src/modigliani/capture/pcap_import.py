"""Import pcap/pcapng files (from Npcap, tcpdump or OpenWrt) into the capture format.

Only packets to or from enrolled devices are kept; everything else is dropped while reading.
Encrypted TLS sessions are reduced to metadata (SNI, sizes, timing): their payload is never stored.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from modigliani.capture.enrollment import Enrollment
from modigliani.capture.model import (
    Capture,
    DeviceRef,
    Direction,
    DnsRecord,
    Endpoint,
    Flow,
    Segment,
    TlsInfo,
    TlsOutcome,
)
from modigliani.infer.decoders import looks_like_tls, tls_client_hello_sni


@dataclass
class _TcpDir:
    chunks: dict[int, tuple[float, bytes]] = field(default_factory=dict)

    def add(self, seq: int, ts: float, payload: bytes) -> None:
        if payload and (seq not in self.chunks or len(payload) > len(self.chunks[seq][1])):
            self.chunks[seq] = (ts, payload)

    def ordered(self) -> list[tuple[float, bytes]]:
        """Reassemble in sequence order, dropping retransmitted bytes."""
        if not self.chunks:
            return []
        base = min(self.chunks)
        items = sorted(((seq - base) % 2**32, ts, data) for seq, (ts, data) in self.chunks.items())
        out: list[tuple[float, bytes]] = []
        end = 0
        for rel, ts, data in items:
            if rel + len(data) <= end:
                continue
            if rel < end:
                data = data[end - rel :]
                rel = end
            out.append((ts, data))
            end = rel + len(data)
        return out


@dataclass
class _Conn:
    device: str
    transport: str
    client: tuple[str, int]
    server: tuple[str, int]
    up: _TcpDir = field(default_factory=_TcpDir)
    down: _TcpDir = field(default_factory=_TcpDir)
    datagrams: list[tuple[float, Direction, bytes]] = field(default_factory=list)


def import_pcap(path: Path, enrollment: Enrollment, name: str | None = None) -> Capture:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapReader

    conns: dict[tuple[str, int, str, int, str], _Conn] = {}
    order: list[tuple[str, int, str, int, str]] = []
    dns_records: list[DnsRecord] = []
    ip_names: dict[str, str] = {}
    seen_devices: dict[str, DeviceRef] = {}

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            ip: Any = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
            if ip is None:
                continue
            src_mac = pkt[Ether].src if Ether in pkt else None
            dst_mac = pkt[Ether].dst if Ether in pkt else None
            dev = enrollment.match(ip=ip.src, mac=src_mac)
            direction = Direction.UP
            if dev is None:
                dev = enrollment.match(ip=ip.dst, mac=dst_mac)
                direction = Direction.DOWN
            if dev is None:
                continue  # not an enrolled device: ignored and never stored
            seen_devices.setdefault(
                dev.name,
                DeviceRef(name=dev.name, mac=dev.mac, ip=dev.ip or (ip.src if direction is Direction.UP else ip.dst)),
            )
            l4: Any = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
            if l4 is None:
                continue
            transport = "tcp" if TCP in pkt else "udp"
            if direction is Direction.UP:
                client, server = (ip.src, int(l4.sport)), (ip.dst, int(l4.dport))
            else:
                client, server = (ip.dst, int(l4.dport)), (ip.src, int(l4.sport))
            if transport == "udp" and 53 in (client[1], server[1]) and DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 1 and dns.qd:
                    qname = dns.qd[0].qname.decode(errors="replace").rstrip(".")
                    answers = []
                    for i in range(dns.ancount or 0):
                        rr = dns.an[i]
                        if getattr(rr, "type", None) in (1, 28):
                            answers.append(str(rr.rdata))
                            ip_names[str(rr.rdata)] = qname
                    dns_records.append(DnsRecord(ts=ts, device=dev.name, qname=qname, answers=answers))
                continue
            key = (client[0], client[1], server[0], server[1], transport)
            if key not in conns:
                conns[key] = _Conn(dev.name, transport, client, server)
                order.append(key)
            c = conns[key]
            payload = bytes(l4.payload) if transport == "udp" else bytes(pkt[TCP].payload)
            if transport == "udp":
                if payload:
                    c.datagrams.append((ts, direction, payload))
            else:
                (c.up if direction is Direction.UP else c.down).add(int(l4.seq), ts, payload)

    flows: list[Flow] = []
    for idx, key in enumerate(order):
        c = conns[key]
        segments: list[Segment] = []
        tls = TlsInfo(outcome=TlsOutcome.PLAINTEXT)
        if c.transport == "udp":
            segments = [Segment.from_bytes(ts, d, p) for ts, d, p in c.datagrams]
        else:
            up, down = c.up.ordered(), c.down.ordered()
            first = up[0][1] if up else b""
            if looks_like_tls(first):
                tls = TlsInfo(
                    outcome=TlsOutcome.UNTESTED,
                    sni=tls_client_hello_sni(first),
                    detail="encrypted session recorded passively; payload not stored",
                )
                segments = [Segment.metadata(ts, Direction.UP, len(p)) for ts, p in up]
                segments += [Segment.metadata(ts, Direction.DOWN, len(p)) for ts, p in down]
            else:
                segments = [Segment.from_bytes(ts, Direction.UP, p) for ts, p in up]
                segments += [Segment.from_bytes(ts, Direction.DOWN, p) for ts, p in down]
            segments.sort(key=lambda s: s.ts)
        if not segments:
            continue
        flows.append(
            Flow(
                index=idx,
                device=c.device,
                transport=cast(Any, c.transport),
                client=Endpoint(host=c.client[0], port=c.client[1]),
                server=Endpoint(host=c.server[0], port=c.server[1]),
                hostname=tls.sni or ip_names.get(c.server[0]),
                tls=tls,
                metadata_only=tls.outcome is TlsOutcome.UNTESTED,
                segments=segments,
            )
        )
    for i, f in enumerate(flows):
        f.index = i
    return Capture(
        name=name or path.stem,
        created=time.time(),
        mode="import",
        devices=list(seen_devices.values()),
        flows=flows,
        dns=dns_records,
    )


def group_by_device(capture: Capture) -> dict[str, list[Flow]]:
    out: dict[str, list[Flow]] = defaultdict(list)
    for f in capture.flows:
        out[f.device].append(f)
    return dict(out)
