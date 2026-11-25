"""Annotations, enrollment, the local CA, proxy routes/recorder decisions, doctor and the web UI."""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography import x509
from fastapi.testclient import TestClient

from modigliani import ca, dpapi
from modigliani.annotate.model import AnnotationKind, AnnotationSet, parse_label
from modigliani.capture.enrollment import (
    Enrollment,
    EnrollmentError,
    normalize_mac,
    parse_linux_neigh,
    parse_windows_arp,
)
from modigliani.capture.model import Capture, TlsOutcome
from modigliani.capture.proxy import ProxyError, Recorder, Route
from modigliani.doctor import check_ca, check_npcap
from modigliani.profile.io import save_profile
from modigliani.web.app import StudioState, create_app
from modigliani.workspace import Workspace
from tests.unit.builders import FlowBuilder, http_request, http_response
from tests.unit.test_profile import _profile


@pytest.mark.parametrize(
    ("label", "variable", "value", "unit", "kind"),
    [
        ("turned on", None, True, None, AnnotationKind.ACTION),
        ("Turned OFF", None, False, None, AnnotationKind.ACTION),
        ("set 22 C", None, 22, "°C", AnnotationKind.ACTION),
        ("set temperature to 21.5 °C", "temperature", 21.5, "°C", AnnotationKind.ACTION),
        ("mode cool", "mode", "cool", None, AnnotationKind.ACTION),
        ("led on", "led", True, None, AnnotationKind.ACTION),
        ("app shows humidity 45 %", "humidity", 45, "%", AnnotationKind.READING),
        ("fan=3", "fan", 3, None, AnnotationKind.ACTION),
    ],
)
def test_parse_label(label: str, variable: str | None, value: object, unit: str | None, kind: AnnotationKind) -> None:
    a = parse_label(label, 1.0)
    assert (a.variable, a.value, a.unit, a.kind) == (variable, value, unit, kind)


def test_annotation_append_is_safe_under_concurrency(tmp_path: Path) -> None:
    path = tmp_path / "c.annotations.json"
    threads = [
        threading.Thread(target=AnnotationSet.append, args=(path, f"set {i} C", float(i), "c", "dev"))
        for i in range(20)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    loaded = AnnotationSet.load(path)
    assert len(loaded.annotations) == 20
    assert [a.value for a in loaded.annotations] == list(range(20))
    assert loaded.for_device("other") == []


def test_enrollment_rules() -> None:
    e = Enrollment()
    with pytest.raises(EnrollmentError):
        e.add("plug", mac="aa:bb:cc:dd:ee:ff", ip=None, owner_confirmed=False)
    e.add("plug", mac="AA-BB-CC-DD-EE-FF", ip="192.168.137.20", owner_confirmed=True)
    e.add("cam", mac=None, ip="192.168.137.30", owner_confirmed=True)
    assert normalize_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"
    assert e.match(mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.9").name == "plug"  # type: ignore[union-attr]
    assert e.match(ip="192.168.137.30").name == "cam"  # type: ignore[union-attr]
    assert e.match(ip="192.168.137.99") is None
    # An IP reassigned to another device (different MAC) is not the enrolled device.
    assert e.match(ip="192.168.137.20", mac="11:22:33:44:55:66") is None


def test_arp_parsers() -> None:
    win = "Interface: 192.168.137.1 --- 0x1a\n  Internet Address      Physical Address      Type\n  192.168.137.20        aa-bb-cc-dd-ee-ff     dynamic\n  192.168.137.255       ff-ff-ff-ff-ff-ff     static\n"
    assert [(n.ip, n.mac) for n in parse_windows_arp(win)] == [("192.168.137.20", "aa:bb:cc:dd:ee:ff")]
    linux = "192.168.1.20 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n192.168.1.1 dev wlan0 FAILED\n"
    assert [(n.ip, n.interface) for n in parse_linux_neigh(linux)] == [("192.168.1.20", "wlan0")]


def test_local_ca_init_issue_and_protection(tmp_path: Path) -> None:
    info = ca.init(tmp_path, use_dpapi=False)
    assert "Modigliani Local CA" in info.subject and info.key_protection.startswith("file")
    with pytest.raises(ca.CaError):
        ca.init(tmp_path)
    cert_pem, _ = ca.issue_leaf(tmp_path, ["api.vendor.example", "10.0.0.5"])
    leaf = x509.load_pem_x509_certificate(cert_pem)
    leaf.verify_directly_issued_by(ca.load_cert(tmp_path))
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "api.vendor.example" in sans.get_values_for_type(x509.DNSName)
    if sys.platform != "win32":
        assert (tmp_path / "ca.key").stat().st_mode & 0o077 == 0
    conf = tmp_path / "conf"
    ca.write_mitmproxy_confdir(tmp_path, conf)
    assert b"PRIVATE KEY" in (conf / "mitmproxy-ca.pem").read_bytes()


@pytest.mark.skipif(not dpapi.AVAILABLE, reason="DPAPI exists only on Windows")
def test_dpapi_protected_ca(tmp_path: Path) -> None:
    blob = dpapi.protect(b"secret\nwith\nnewlines")
    assert dpapi.unprotect(blob) == b"secret\nwith\nnewlines"
    info = ca.init(tmp_path, use_dpapi=True)
    assert info.key_protection == "dpapi" and (tmp_path / "ca.key.dpapi").exists()
    assert ca.load_key(tmp_path).key_size == 2048


def test_route_parsing() -> None:
    r = Route.parse("https:127.0.0.1:18443=api.vendor.example@127.0.0.1:28443")
    assert (r.scheme, r.listen_host, r.listen_port, r.hostname, r.upstream_host, r.upstream_port) == (
        "https",
        "127.0.0.1",
        18443,
        "api.vendor.example",
        "127.0.0.1",
        28443,
    )
    assert r.mode() == "reverse:https://127.0.0.1:28443@127.0.0.1:18443"
    d = Route.parse("tls:8883=mqtt.vendor.example")
    assert (d.upstream_host, d.upstream_port, d.listen_host) == ("mqtt.vendor.example", 8883, "0.0.0.0")
    with pytest.raises(ProxyError):
        Route.parse("ftp:21=x")
    w = Route.parse("https:443=*")
    assert w.wildcard and w.mode() == "reverse:https://127.0.0.1:443@0.0.0.0:443"


def test_wildcard_route_targets_the_sni_host() -> None:
    enr = Enrollment()
    enr.add("plug", mac=None, ip="10.0.0.2", owner_confirmed=True)
    rec = Recorder(
        enrollment=enr,
        routes=[Route.parse("https:443=*")],
        name="t",
        resolver=lambda name: "203.0.113.5" if name == "api.vendor.example" else None,
    )
    client = SimpleNamespace(sockname=("0.0.0.0", 443), sni="api.vendor.example")
    data = SimpleNamespace(client=client, server=SimpleNamespace(address=("127.0.0.1", 443), sni=None, error=None))
    rec.server_connect(data)
    assert data.server.address == ("203.0.113.5", 443) and data.server.sni == "api.vendor.example"
    nosni = SimpleNamespace(
        client=SimpleNamespace(sockname=("0.0.0.0", 443), sni=None),
        server=SimpleNamespace(address=None, sni=None, error=None),
    )
    rec.server_connect(nosni)
    assert nosni.server.error


def _client(ip: str, port: int = 18443) -> Any:
    return SimpleNamespace(
        id=f"{ip}:{port}", peername=(ip, 50000), sockname=("127.0.0.1", port), error=None, transport_protocol="tcp"
    )


def test_recorder_refuses_unenrolled_and_tracks_tls_rejection() -> None:
    enr = Enrollment()
    enr.add("hub", mac=None, ip="127.0.0.5", owner_confirmed=True)
    rec = Recorder(enrollment=enr, routes=[Route.parse("https:127.0.0.1:18443=hub.example@127.0.0.1:1")], name="t")
    stranger = _client("127.0.0.9")
    rec.client_connected(stranger)
    assert stranger.error == "not an enrolled device"
    hub = _client("127.0.0.5")
    rec.client_connected(hub)
    assert hub.error is None
    rec.tls_clienthello(
        SimpleNamespace(context=SimpleNamespace(client=hub), client_hello=SimpleNamespace(sni="hub.example"))
    )
    rec.tls_failed_client(
        SimpleNamespace(context=SimpleNamespace(client=hub), conn=SimpleNamespace(error="unknown ca"))
    )
    assert ("127.0.0.5", "hub.example") in rec.rejecting
    cap = rec.capture()
    assert cap.flows[0].tls.outcome is TlsOutcome.REJECTED_LOCAL_CA and cap.flows[0].metadata_only
    assert all(s.data is None for s in cap.flows[0].segments)


def test_doctor_checks(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    assert check_ca(ws).status == "warn"
    ca.init(ws.ca_dir, use_dpapi=False)
    assert check_ca(ws).status == "ok"
    npcap = check_npcap()
    if sys.platform == "win32":
        assert npcap.status in ("ok", "fail") and ("npcap.com" in npcap.detail or npcap.status == "ok")
    else:
        assert npcap.status == "skip"


def test_web_ui(tmp_path: Path) -> None:
    f = FlowBuilder(0).up(1.0, http_request("GET", "/x")).down(1.1, http_response(200, {"a": 1}))
    cap = Capture(name="c", created=0.0, mode="proxy", flows=[f.flow])
    cap_path = tmp_path / "c.mcap.json"
    cap.save(cap_path)
    profile_path = tmp_path / "p.yaml"
    save_profile(_profile(), profile_path)
    client = TestClient(create_app(StudioState(cap_path, tmp_path / "c.annotations.json", profile_path)))
    assert "Modigliani Studio" in client.get("/").text
    assert client.get("/api/timeline").json()[0]["summary"].startswith("GET api.vendor.example/x")
    assert client.post("/api/annotations", json={"label": "set 21 C", "ts": 5.0}).json()["value"] == 21
    assert len(client.get("/api/annotations").json()) == 1
    assert client.delete("/api/annotations/0").json() == {"remaining": 0}
    prof = client.get("/api/profile").json()
    assert prof["errors"] == []
    bad = client.put(
        "/api/profile", json={"text": prof["text"].replace("schema_version: 1", "schema_version: 9")}
    ).json()
    assert not bad["saved"] and bad["errors"]
    assert client.put("/api/profile", json={"text": prof["text"]}).json()["saved"]
    preview = client.get("/api/profile/scrub").json()
    assert "AB-998877" not in preview["result"] and preview["changes"]
