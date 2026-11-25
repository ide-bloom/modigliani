"""The Modigliani capture format.

Every capture path (live hotspot capture, pcap import, proxy mode) produces the same
bundle: per-device flows made of timestamped byte segments. Decoders work on byte
streams so that one decoding path serves passive and proxy captures alike.
"""

from __future__ import annotations

import base64
import gzip
import json
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

CAPTURE_FORMAT = "modigliani-capture"
CAPTURE_VERSION = 1


class Direction(StrEnum):
    UP = "up"  # device -> cloud
    DOWN = "down"  # cloud -> device


class TlsOutcome(StrEnum):
    PLAINTEXT = "plaintext"
    # Proxy mode terminated TLS with a certificate from the local CA and the device accepted it.
    ACCEPTED_LOCAL_CA = "accepted_local_ca"
    # The device aborted the handshake when offered a local-CA certificate.
    REJECTED_LOCAL_CA = "rejected_local_ca"
    # Encrypted traffic forwarded untouched; only metadata (sizes, timing) was kept.
    PASSTHROUGH = "passthrough"
    # Passive capture of a TLS session with the vendor: acceptance of the local CA is untested.
    UNTESTED = "untested"


class Endpoint(BaseModel):
    host: str
    port: int


class TlsInfo(BaseModel):
    outcome: TlsOutcome = TlsOutcome.PLAINTEXT
    sni: str | None = None
    detail: str = ""


class Segment(BaseModel):
    ts: float
    dir: Direction
    size: int
    # None when the segment is metadata-only (encrypted traffic we must not and cannot read).
    data: str | None = Field(default=None, description="base64 payload")

    @classmethod
    def from_bytes(cls, ts: float, direction: Direction, payload: bytes) -> Segment:
        return cls(ts=ts, dir=direction, size=len(payload), data=base64.b64encode(payload).decode())

    @classmethod
    def metadata(cls, ts: float, direction: Direction, size: int) -> Segment:
        return cls(ts=ts, dir=direction, size=size, data=None)

    def payload(self) -> bytes:
        return base64.b64decode(self.data) if self.data is not None else b""


class Flow(BaseModel):
    index: int
    device: str
    transport: Literal["tcp", "udp"]
    client: Endpoint
    server: Endpoint
    hostname: str | None = None
    tls: TlsInfo = Field(default_factory=TlsInfo)
    metadata_only: bool = False
    segments: list[Segment] = Field(default_factory=list)

    @property
    def start(self) -> float:
        return self.segments[0].ts if self.segments else 0.0

    @property
    def end(self) -> float:
        return self.segments[-1].ts if self.segments else 0.0

    def stream(self, direction: Direction) -> tuple[bytes, list[tuple[int, float]]]:
        """Concatenate one direction's payload; also return (offset, ts) marks per segment."""
        buf = bytearray()
        marks: list[tuple[int, float]] = []
        for seg in self.segments:
            if seg.dir is direction and seg.data is not None:
                marks.append((len(buf), seg.ts))
                buf.extend(seg.payload())
        return bytes(buf), marks


class DnsRecord(BaseModel):
    ts: float
    device: str
    qname: str
    answers: list[str] = Field(default_factory=list)


class DeviceRef(BaseModel):
    name: str
    mac: str | None = None
    ip: str | None = None


class Capture(BaseModel):
    format: Literal["modigliani-capture"] = "modigliani-capture"
    version: int = CAPTURE_VERSION
    name: str
    created: float
    mode: Literal["passive", "proxy", "import"]
    devices: list[DeviceRef] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    dns: list[DnsRecord] = Field(default_factory=list)

    def flows_for(self, device: str | None) -> list[Flow]:
        return [f for f in self.flows if device is None or f.device == device]

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.model_dump_json(indent=None).encode()
        if path.suffix == ".gz":
            data = gzip.compress(data)
        path.write_bytes(data)

    @classmethod
    def load(cls, path: Path) -> Capture:
        raw = path.read_bytes()
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        return cls.model_validate(json.loads(raw))
