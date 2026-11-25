"""Device enrollment.

Modigliani only resolves, proxies or records traffic for devices the user enrolled and
confirmed they own. Device discovery is passive: it reads the operating system's
neighbour (ARP) table and never scans the network.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from pydantic import BaseModel, Field

_MAC_RE = re.compile(r"^([0-9a-f]{2})([:-]?)([0-9a-f]{2})(\2[0-9a-f]{2}){4}$", re.IGNORECASE)


class EnrollmentError(ValueError):
    pass


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower()
    if not _MAC_RE.match(mac):
        raise EnrollmentError(f"not a MAC address: {mac!r}")
    hexdigits = re.sub(r"[^0-9a-f]", "", mac)
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


class EnrolledDevice(BaseModel):
    name: str
    mac: str | None = None
    ip: str | None = None
    owner_confirmed: bool
    enrolled_at: float = Field(default_factory=time.time)


class Enrollment(BaseModel):
    devices: list[EnrolledDevice] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> Enrollment:
        if not path.exists():
            return cls()
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    def add(self, name: str, *, mac: str | None, ip: str | None, owner_confirmed: bool) -> EnrolledDevice:
        if not owner_confirmed:
            raise EnrollmentError("you must confirm that you own the device before enrolling it")
        if mac is None and ip is None:
            raise EnrollmentError("a device needs a MAC address or an IP address")
        if any(d.name == name for d in self.devices):
            raise EnrollmentError(f"a device named {name!r} is already enrolled")
        dev = EnrolledDevice(name=name, mac=normalize_mac(mac) if mac else None, ip=ip, owner_confirmed=True)
        self.devices.append(dev)
        return dev

    def remove(self, name: str) -> bool:
        before = len(self.devices)
        self.devices = [d for d in self.devices if d.name != name]
        return len(self.devices) != before

    def match(self, *, ip: str | None = None, mac: str | None = None) -> EnrolledDevice | None:
        """Return the enrolled device for an address, or None if it is not enrolled.

        A MAC match wins over an IP match because hotspot IPs are reassigned by DHCP.
        """
        norm = None
        if mac:
            try:
                norm = normalize_mac(mac)
            except EnrollmentError:
                norm = None
        for dev in self.devices:
            if norm and dev.mac == norm and dev.owner_confirmed:
                return dev
        for dev in self.devices:
            if ip and dev.ip == ip and dev.owner_confirmed and (dev.mac is None or norm is None):
                return dev
        return None


class Neighbor(BaseModel):
    ip: str
    mac: str
    interface: str = ""


_WIN_ARP_IFACE = re.compile(r"^Interface:\s+(\S+)")
_WIN_ARP_ROW = re.compile(r"^\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)", re.IGNORECASE)
_LINUX_NEIGH = re.compile(r"^(\S+)\s+dev\s+(\S+)\s+lladdr\s+([0-9a-f:]{17})", re.IGNORECASE)


def parse_windows_arp(text: str) -> list[Neighbor]:
    out: list[Neighbor] = []
    iface = ""
    for line in text.splitlines():
        if m := _WIN_ARP_IFACE.match(line):
            iface = m.group(1)
        elif (m := _WIN_ARP_ROW.match(line)) and m.group(3).lower() == "dynamic":
            mac = normalize_mac(m.group(2))
            if mac != "ff:ff:ff:ff:ff:ff":
                out.append(Neighbor(ip=m.group(1), mac=mac, interface=iface))
    return out


def parse_linux_neigh(text: str) -> list[Neighbor]:
    out: list[Neighbor] = []
    for line in text.splitlines():
        if m := _LINUX_NEIGH.match(line):
            out.append(Neighbor(ip=m.group(1), mac=normalize_mac(m.group(3)), interface=m.group(2)))
    return out


def visible_devices() -> list[Neighbor]:
    """Devices the OS already knows about (from ARP traffic it has seen). No probing."""
    try:
        if os.name == "nt":
            text = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False).stdout
            return parse_windows_arp(text)
        text = subprocess.run(["ip", "neigh"], capture_output=True, text=True, check=False).stdout
        return parse_linux_neigh(text)
    except OSError:
        return []
