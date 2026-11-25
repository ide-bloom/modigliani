"""`modigliani doctor`: check Npcap, the hotspot, DNS, the local CA and the server."""

from __future__ import annotations

import http.client
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from modigliani import ca
from modigliani.capture.hotspot import WINDOWS_HOTSPOT_IP
from modigliani.workspace import Workspace

NPCAP_URL = "https://npcap.com/#download"


@dataclass
class Check:
    name: str
    status: str  # ok | warn | fail | skip
    detail: str


def check_npcap() -> Check:
    if sys.platform != "win32":
        return Check(
            "Npcap", "skip", "Not Windows: live capture uses libpcap/raw sockets (run as root or grant CAP_NET_RAW)."
        )
    system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    dll = Path(system_root) / "System32" / "Npcap" / "wpcap.dll"
    if dll.exists():
        return Check("Npcap", "ok", f"found {dll}")
    return Check(
        "Npcap",
        "fail",
        f"Npcap is not installed. Download it from {NPCAP_URL} and install it with "
        "'WinPcap API-compatible mode' enabled. Modigliani cannot bundle Npcap because its license "
        "forbids redistribution. Proxy mode and pcap import work without it.",
    )


def check_hotspot() -> Check:
    if sys.platform != "win32":
        return Check("Hotspot", "skip", "Windows Mobile Hotspot only applies to Windows; use router or gateway mode.")
    try:
        out = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-NetIPAddress -IPAddress {WINDOWS_HOTSPOT_IP} -ErrorAction SilentlyContinue).InterfaceAlias",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Check("Hotspot", "warn", f"could not query network adapters: {exc}")
    if out:
        return Check("Hotspot", "ok", f"Mobile Hotspot is on (adapter '{out}', {WINDOWS_HOTSPOT_IP})")
    return Check(
        "Hotspot", "warn", "Mobile Hotspot looks off. Turn it on in Settings > Network & internet > Mobile hotspot."
    )


def check_dns(probe: str) -> Check:
    try:
        addrs = {str(a[4][0]) for a in socket.getaddrinfo(probe, None)}
    except OSError as exc:
        return Check("DNS", "fail", f"cannot resolve {probe}: {exc}")
    detail = f"{probe} resolves to {', '.join(sorted(addrs))}"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("0.0.0.0", 53))
        detail += "; UDP port 53 is free for router-mode DNS"
    except OSError:
        detail += "; UDP port 53 is busy or needs elevated rights (router-mode DNS can use --dns-port)"
    return Check("DNS", "ok", detail)


def check_ca(ws: Workspace) -> Check:
    if not ca.exists(ws.ca_dir):
        return Check(
            "Local CA",
            "warn",
            "no local CA yet; run `modigliani ca init` (needed for proxy mode and HTTPS/MQTT-TLS revival)",
        )
    try:
        info = ca.info(ws.ca_dir)
        ca.load_key(ws.ca_dir)
    except Exception as exc:  # noqa: BLE001 - report any decryption/parsing failure
        return Check("Local CA", "fail", f"CA present but unusable: {exc}")
    return Check(
        "Local CA", "ok", f"{info.subject}, expires {info.not_after:%Y-%m-%d}, key protection: {info.key_protection}"
    )


def check_server(url: str) -> Check:
    parts = urlsplit(url)
    try:
        conn = http.client.HTTPConnection(parts.hostname or "127.0.0.1", parts.port or 8080, timeout=3)
        conn.request("GET", "/api/health")
        resp = conn.getresponse()
        body = resp.read().decode(errors="replace")
    except OSError as exc:
        return Check("Server", "warn", f"no Modigliani Server at {url} ({exc}); start it with `modigliani-server`")
    if resp.status == 200:
        return Check("Server", "ok", f"{url}: {body.strip()}")
    return Check("Server", "fail", f"{url} answered HTTP {resp.status}")


def run_checks(ws: Workspace, server_url: str, probe: str) -> list[Check]:
    return [check_npcap(), check_hotspot(), check_dns(probe), check_ca(ws), check_server(server_url)]
