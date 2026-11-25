"""Router-mode DNS: the user's router sends the device's DNS queries to Modigliani.

For enrolled devices the query is recorded and answered either with the real address
(observe mode, to learn hostnames) or with this PC's address (proxy mode, so the device's
connections reach the recorder). Queries from other clients are forwarded unchanged and
not stored.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from dnslib import QTYPE, RR, A, DNSRecord
from dnslib.server import BaseResolver, DNSHandler, DNSServer

from modigliani.capture.enrollment import Enrollment
from modigliani.capture.model import DnsRecord


@dataclass
class RouterDns:
    enrollment: Enrollment
    upstream: str = "1.1.1.1"
    answer_ip: str | None = None  # None: observe only (answer with the real address)
    records: list[DnsRecord] = field(default_factory=list)
    real: dict[str, list[str]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def forward(self, request: DNSRecord) -> DNSRecord:
        raw = request.send(self.upstream, 53, timeout=3)
        return DNSRecord.parse(raw)

    def handle(self, request: DNSRecord, client_ip: str) -> DNSRecord:
        device = self.enrollment.match(ip=client_ip)
        if device is None:
            return self.forward(request)
        qname = str(request.q.qname).rstrip(".")
        try:
            upstream_reply = self.forward(request)
            answers = [str(rr.rdata) for rr in upstream_reply.rr if rr.rtype in (QTYPE.A, QTYPE.AAAA)]
        except (TimeoutError, OSError):
            upstream_reply, answers = request.reply(), []
        with self.lock:
            self.records.append(DnsRecord(ts=time.time(), device=device.name, qname=qname, answers=answers))
            if answers:
                self.real[qname.lower()] = answers
        if self.answer_ip is None or request.q.qtype not in (QTYPE.A, QTYPE.ANY):
            return upstream_reply
        reply = request.reply()
        reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.answer_ip), ttl=30))
        return reply

    def resolve_real(self, hostname: str) -> str | None:
        with self.lock:
            hits = self.real.get(hostname.lower())
        return hits[0] if hits else None


class _Resolver(BaseResolver):  # type: ignore[misc]
    def __init__(self, router: RouterDns) -> None:
        self.router = router

    def resolve(self, request: DNSRecord, handler: DNSHandler) -> DNSRecord:
        return self.router.handle(request, handler.client_address[0])


def start_dns(router: RouterDns, address: str = "0.0.0.0", port: int = 53) -> DNSServer:
    server = DNSServer(_Resolver(router), address=address, port=port)
    server.start_thread()
    return server
