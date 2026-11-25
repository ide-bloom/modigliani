"""pcap import: reassembly, enrollment filtering, DNS names and TLS metadata-only handling."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Any

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from modigliani.capture.enrollment import Enrollment
from modigliani.capture.model import TlsOutcome
from modigliani.capture.pcap_import import import_pcap
from modigliani.infer.sessions import build_sessions
from tests.unit.builders import http_request, http_response, mqtt_connect, mqtt_publish

DEV_MAC, DEV_IP, CLOUD_IP, OTHER_IP = "aa:bb:cc:00:11:22", "192.168.137.20", "203.0.113.10", "192.168.137.99"


def _tcp(src: str, dst: str, sport: int, dport: int, seq: int, payload: bytes, t: float, mac: str = DEV_MAC) -> Any:
    eth = (
        Ether(src=mac, dst="02:00:00:00:00:01")
        if src.startswith("192.168")
        else Ether(src="02:00:00:00:00:01", dst=mac)
    )
    pkt = eth / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags="PA") / payload
    pkt.time = t
    return pkt


def _client_hello() -> bytes:
    ctx = ssl.create_default_context()
    a, b = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(a, b, server_hostname="secure.vendor.example")
    with pytest.raises(ssl.SSLWantReadError):
        obj.do_handshake()
    return b.read()


def test_import_filters_reassembles_and_names(tmp_path: Path) -> None:
    req = http_request("POST", "/api/report", {"t": 21})
    resp = http_response(200, {"ok": True})
    hello = _client_hello()
    pkts = [
        # DNS answer tells us the cloud's hostname.
        Ether(src="02:00:00:00:00:01", dst=DEV_MAC)
        / IP(src="192.168.137.1", dst=DEV_IP)
        / UDP(sport=53, dport=40000)
        / DNS(qr=1, qd=DNSQR(qname="api.vendor.example"), an=DNSRR(rrname="api.vendor.example", rdata=CLOUD_IP)),
        # HTTP request split in two segments, delivered out of order, with a retransmission.
        _tcp(DEV_IP, CLOUD_IP, 40001, 80, 1000 + 10, req[10:], 1.1),
        _tcp(DEV_IP, CLOUD_IP, 40001, 80, 1000, req[:10], 1.0),
        _tcp(DEV_IP, CLOUD_IP, 40001, 80, 1000, req[:10], 1.05),
        _tcp(CLOUD_IP, DEV_IP, 80, 40001, 5000, resp, 1.2),
        # MQTT session.
        _tcp(DEV_IP, CLOUD_IP, 40002, 1883, 1, mqtt_connect("dev-1") + mqtt_publish("d/1/t", b"{}"), 2.0),
        # TLS: metadata only.
        _tcp(DEV_IP, CLOUD_IP, 40003, 443, 1, hello, 3.0),
        _tcp(CLOUD_IP, DEV_IP, 443, 40003, 1, b"\x16\x03\x03" + b"\x00" * 50, 3.1),
        # Another client on the hotspot: must be dropped entirely.
        _tcp(OTHER_IP, CLOUD_IP, 40009, 80, 1, http_request("GET", "/private"), 4.0, mac="de:ad:be:ef:00:01"),
    ]
    path = tmp_path / "router.pcap"
    wrpcap(str(path), pkts)
    enr = Enrollment()
    enr.add("plug", mac=DEV_MAC, ip=None, owner_confirmed=True)
    cap = import_pcap(path, enr, "router")
    assert {f.device for f in cap.flows} == {"plug"}
    assert all(f.client.host == DEV_IP for f in cap.flows)
    assert cap.dns[0].qname == "api.vendor.example" and cap.dns[0].answers == [CLOUD_IP]
    http_flow = next(f for f in cap.flows if f.server.port == 80)
    assert http_flow.hostname == "api.vendor.example"
    tls_flow = next(f for f in cap.flows if f.server.port == 443)
    assert tls_flow.tls.outcome is TlsOutcome.UNTESTED and tls_flow.tls.sni == "secure.vendor.example"
    assert tls_flow.metadata_only and all(s.data is None for s in tls_flow.segments)
    sess = build_sessions([cap], "plug")
    assert [(e.req.method, e.req.path, e.resp.status if e.resp else None) for e in sess.http] == [
        ("POST", "/api/report", 200)
    ]
    assert sess.mqtt[0].connect is not None and sess.mqtt[0].connect.client_id == "dev-1"
    assert "/private" not in cap.model_dump_json()
