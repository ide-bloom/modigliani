"""Live capture on the Windows Mobile Hotspot interface (or any interface) with Npcap/libpcap.

The BPF filter only admits enrolled devices' frames, so other clients' traffic never
reaches Modigliani at all. Npcap is installed by the user (its license forbids bundling).
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from modigliani.capture.enrollment import Enrollment

# Windows Internet Connection Sharing always gives the hotspot adapter this address.
WINDOWS_HOTSPOT_IP = "192.168.137.1"


class CaptureUnavailableError(RuntimeError):
    pass


def bpf_filter(enrollment: Enrollment) -> str:
    terms: list[str] = []
    for d in enrollment.devices:
        if not d.owner_confirmed:
            continue
        if d.mac:
            terms.append(f"ether host {d.mac}")
        elif d.ip:
            terms.append(f"host {d.ip}")
    if not terms:
        raise CaptureUnavailableError("no enrolled devices; run `modigliani enroll` first")
    return " or ".join(terms)


def find_hotspot_interface() -> str | None:
    try:
        from scapy.config import conf
    except ImportError:
        return None
    try:
        for iface in conf.ifaces.values():
            ips: Any = getattr(iface, "ips", {}) or {}
            addrs = list(ips.get(4, [])) if isinstance(ips, dict) else []
            if WINDOWS_HOTSPOT_IP in addrs or getattr(iface, "ip", None) == WINDOWS_HOTSPOT_IP:
                return str(iface.name)
    except Exception:  # noqa: BLE001 - scapy raises various errors without Npcap
        return None
    return None


def live_capture(
    interface: str | None,
    enrollment: Enrollment,
    seconds: float,
    out: Path,
    stop: threading.Event | None = None,
) -> Path:
    try:
        from scapy.sendrecv import AsyncSniffer
        from scapy.utils import wrpcap
    except ImportError as exc:  # pragma: no cover - scapy is a dependency
        raise CaptureUnavailableError(str(exc)) from exc
    iface = interface or find_hotspot_interface()
    if iface is None:
        raise CaptureUnavailableError(
            "no capture interface found. Turn on Windows Mobile Hotspot, or pass --interface. "
            "Run `modigliani doctor` to check Npcap."
        )
    try:
        sniffer = AsyncSniffer(iface=iface, filter=bpf_filter(enrollment), store=True)
        sniffer.start()
    except Exception as exc:
        raise CaptureUnavailableError(f"could not start capture on {iface}: {exc}") from exc
    deadline = time.monotonic() + seconds
    try:
        while time.monotonic() < deadline and not (stop and stop.is_set()):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    packets = sniffer.stop()
    out.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out), packets or [])
    return out
