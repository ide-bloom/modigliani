"""Binary protocols: stream framing, checksum search and frame-layout inference.

Framing rules, tried in order (docs/inference.md, "Raw framing"):
1. delimiter: the stream ends with a common delimiter and splits into >= 3 non-empty frames;
2. length-prefixed: a 1/2/4-byte length field at offset 0..3 that, with a constant adjustment,
   walks the stream exactly to its end in >= 2 frames;
3. fixed records: the stream is a multiple of a record size whose first byte is constant;
4. otherwise each transport segment is a message.

Checksum rule: an algorithm/coverage combination must hold for every frame and at least two
distinct frames, so a single coincidence cannot produce a checksum.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

from modigliani.profile.model import Checksum, Frame, FrameField, Framing, LengthField

# ------------------------------------------------------------------ checksum algorithms


def sum8(b: bytes) -> int:
    return sum(b) & 0xFF


def xor8(b: bytes) -> int:
    v = 0
    for c in b:
        v ^= c
    return v


def crc8(b: bytes) -> int:
    crc = 0
    for c in b:
        crc ^= c
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def sum16(b: bytes) -> int:
    return sum(b) & 0xFFFF


def crc16_ccitt(b: bytes) -> int:
    crc = 0xFFFF
    for c in b:
        crc ^= c << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def crc16_modbus(b: bytes) -> int:
    crc = 0xFFFF
    for c in b:
        crc ^= c
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def crc32(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


ALGORITHMS: dict[str, tuple[Callable[[bytes], int], int]] = {
    "sum8": (sum8, 1),
    "xor8": (xor8, 1),
    "crc8": (crc8, 1),
    "sum16": (sum16, 2),
    "crc16_ccitt": (crc16_ccitt, 2),
    "crc16_modbus": (crc16_modbus, 2),
    "crc32": (crc32, 4),
}


def _span(frame_len: int, start: int, end: int) -> tuple[int, int]:
    return start, (frame_len + end if end <= 0 else end)


def compute_checksum(frame: bytes, ck: Checksum) -> int:
    fn, _ = ALGORITHMS[ck.algorithm]
    s, e = _span(len(frame), ck.start, ck.end)
    return fn(frame[s:e])


def read_checksum(frame: bytes, ck: Checksum) -> int:
    _, width = ALGORITHMS[ck.algorithm]
    pos = ck.offset if ck.offset >= 0 else len(frame) + ck.offset
    return int.from_bytes(frame[pos : pos + width], ck.endian)


def verify_checksum(frame: bytes, ck: Checksum) -> bool:
    try:
        return compute_checksum(frame, ck) == read_checksum(frame, ck)
    except (IndexError, ValueError):
        return False


def find_checksum(frames: list[bytes]) -> Checksum | None:
    distinct = {f for f in frames if len(f) >= 3}
    if len(distinct) < 2:
        return None
    for name, (_, width) in ALGORITHMS.items():
        for endian in ("big", "little") if width > 1 else ("big",):
            for start in range(4):
                ck = Checksum(algorithm=cast(Any, name), offset=-width, start=start, end=-width, endian=endian)
                if all(len(f) > start + width and verify_checksum(f, ck) for f in distinct):
                    return ck
    return None


# ------------------------------------------------------------------ field codecs

FIELD_TYPES: dict[str, tuple[str, int]] = {
    "u8": (">B", 1),
    "i8": (">b", 1),
    "u16be": (">H", 2),
    "u16le": ("<H", 2),
    "i16be": (">h", 2),
    "i16le": ("<h", 2),
    "u32be": (">I", 4),
    "u32le": ("<I", 4),
    "i32be": (">i", 4),
    "i32le": ("<i", 4),
}


def read_field(frame: bytes, offset: int, ftype: str) -> int | None:
    fmt, width = FIELD_TYPES[ftype]
    if offset + width > len(frame):
        return None
    v: int = struct.unpack_from(fmt, frame, offset)[0]
    return v


def decode_frame(frame: bytes, layout: Frame) -> dict[str, float | int]:
    out: dict[str, float | int] = {}
    for f in layout.fields:
        raw = read_field(frame, f.offset, f.type)
        if raw is None:
            continue
        out[f.name] = raw * f.scale if f.scale != 1.0 else raw
    return out


def encode_frame(layout: Frame, values: dict[str, float | int]) -> bytes:
    """Build a frame from a layout (used by tests and the replay tester; the server has its own)."""
    size = layout.length or max((f.offset + FIELD_TYPES[f.type][1] for f in layout.fields), default=0)
    buf = bytearray(size)
    for f in layout.fields:
        fmt, _ = FIELD_TYPES[f.type]
        raw = f.const if f.const is not None else round(float(values.get(f.name, 0)) / f.scale)
        struct.pack_into(fmt, buf, f.offset, raw)
    if layout.length_field:
        lf = layout.length_field
        struct.pack_into(FIELD_TYPES[lf.type][0], buf, lf.offset, len(buf) - lf.adjust)
    if layout.checksum:
        ck = layout.checksum
        _, width = ALGORITHMS[ck.algorithm]
        pos = ck.offset if ck.offset >= 0 else len(buf) + ck.offset
        buf[pos : pos + width] = compute_checksum(bytes(buf), ck).to_bytes(width, ck.endian)
    return bytes(buf)


# ------------------------------------------------------------------ layout inference


@dataclass
class NumericHint:
    """A value the user saw or set at a moment in time (from annotations)."""

    ts: float
    value: float
    name: str
    is_bool: bool = False
    # Window relative to ts in which a frame must carry the value. Actions show up after the
    # tap; readings were already on screen, so they come from frames just before it.
    lo: float = 0.0
    hi: float = 20.0


@dataclass
class FieldMatch:
    name: str
    offset: int
    type: str
    scale: float
    hits: int
    refs: list[int] = field(default_factory=list)


_SCALES = (1.0, 0.1, 0.01, 0.5)


def _close(a: float, b: float) -> bool:
    return abs(a - b) <= max(1e-6, abs(b) * 1e-6)


def match_hints(frames: list[tuple[float, bytes]], hints: list[NumericHint], free: set[int]) -> list[FieldMatch]:
    """Find fields whose decoded value equals what the user saw/set shortly after each hint."""
    if not frames or not hints:
        return []
    length = len(frames[0][1])
    by_name: dict[str, list[NumericHint]] = {}
    for h in hints:
        by_name.setdefault(h.name, []).append(h)
    matches: list[FieldMatch] = []
    taken: set[int] = set()
    constant = {o for o in range(length) if len({fr[o] for _, fr in frames}) == 1}
    for name, group in by_name.items():
        best: FieldMatch | None = None
        is_action = all(h.is_bool for h in group)
        types = ["u8"] if is_action else list(FIELD_TYPES)
        for ftype in types:
            width = FIELD_TYPES[ftype][1]
            for off in range(length - width + 1):
                if not all(o in free and o not in taken for o in range(off, off + width)):
                    continue
                # A switchable state must change at least once; readings may be constant (battery).
                if is_action and off in constant:
                    continue
                for scale in (1.0,) if group[0].is_bool else _SCALES:
                    hits, refs = 0, []
                    for h in group:
                        for idx, (ts, fr) in enumerate(frames):
                            if not h.ts + h.lo <= ts <= h.ts + h.hi:
                                continue
                            raw = read_field(fr, off, ftype)
                            if raw is not None and _close(raw * scale, h.value):
                                hits += 1
                                refs.append(idx)
                                break
                    if hits and (
                        best is None or hits > best.hits or (hits == best.hits and width < FIELD_TYPES[best.type][1])
                    ):
                        best = FieldMatch(name, off, ftype, scale, hits, refs)
        if best is not None and best.type == "u8" and best.offset - 1 in free and best.offset - 1 not in taken:
            # A matching byte preceded by a byte that is always zero is the low half of a
            # big-endian 16-bit value that simply has not exceeded 255 yet.
            if all(fr[best.offset - 1] == 0 for _, fr in frames):
                signed = any(w in name for w in ("temp", "temperature"))
                best = FieldMatch(
                    name, best.offset - 1, "i16be" if signed else "u16be", best.scale, best.hits, best.refs
                )
        if best is not None and best.hits >= max(1, (len(group) + 1) // 2):
            matches.append(best)
            taken.update(range(best.offset, best.offset + FIELD_TYPES[best.type][1]))
    return matches


def find_length_field(frames: list[bytes], checksum_width: int) -> LengthField | None:
    for off in range(4):
        for ftype in ("u8", "u16be", "u16le"):
            width = FIELD_TYPES[ftype][1]
            # Natural conventions first: counts bytes after the field excluding the checksum,
            # including the checksum, the whole frame, or everything but the checksum.
            for adjust in dict.fromkeys((off + width + checksum_width, off + width, 0, checksum_width)):
                if all(
                    len(f) > off + width
                    and (v := read_field(f, off, ftype)) is not None
                    and v + adjust == len(f)
                    and v > 0
                    for f in frames
                ):
                    return LengthField(offset=off, type=ftype, adjust=adjust)
    return None


def infer_frame(
    frame_id: str,
    frames: list[tuple[float, bytes]],
    hints: list[NumericHint],
    checksum: Checksum | None,
    length_field: LengthField | None = None,
) -> tuple[Frame, list[FieldMatch]]:
    """Infer a fixed-length frame layout. Frames must share one length."""
    data = [f for _, f in frames]
    length = len(data[0])
    ck_width = ALGORITHMS[checksum.algorithm][1] if checksum else 0
    ck_pos = set(range(length - ck_width, length)) if checksum else set()
    # The caller passes a length field found across all frame types of a device; a single
    # frame type alone is ambiguous (any constant byte can look like a length).
    if length_field is None:
        length_field = find_length_field(data, ck_width)
    lf_pos = (
        set(range(length_field.offset, length_field.offset + FIELD_TYPES[length_field.type][1]))
        if length_field
        else set()
    )
    free = set(range(length)) - ck_pos - lf_pos
    matches = match_hints(frames, hints, free)
    fields: list[FrameField] = []
    claimed = set(ck_pos) | lf_pos
    for m in matches:
        fields.append(FrameField(name=m.name, offset=m.offset, type=cast(Any, m.type), scale=m.scale))
        claimed.update(range(m.offset, m.offset + FIELD_TYPES[m.type][1]))
    off = 0
    while off < length:
        if off in claimed:
            off += 1
            continue
        column = {f[off] for f in data}
        if len(column) == 1:
            fields.append(FrameField(name=f"const_{off}", offset=off, type="u8", const=next(iter(column))))
            off += 1
            continue
        nxt = off + 1
        if nxt < length and nxt not in claimed and len({f[nxt] for f in data}) > 1:
            hi = {f[off] for f in data}
            # A slowly changing byte followed by a fast one is the classic big-endian 16-bit reading.
            if len(hi) <= max(2, len({f[nxt] for f in data}) // 4):
                fields.append(FrameField(name=f"field_{off}", offset=off, type="u16be"))
                off += 2
                continue
        fields.append(FrameField(name=f"field_{off}", offset=off, type="u8"))
        off += 1
    fields.sort(key=lambda f: f.offset)
    layout = Frame(id=frame_id, length=length, fields=fields, length_field=length_field, checksum=checksum)
    return layout, matches


# ------------------------------------------------------------------ stream framing

_DELIMITERS = (b"\r\n", b"\n", b"\x00", b"\x7e", b"\x03")


def infer_framing(streams: list[bytes]) -> Framing:
    streams = [s for s in streams if s]
    if not streams:
        return Framing(kind="datagram")
    for delim in _DELIMITERS:
        if all(s.endswith(delim) for s in streams):
            parts = [p for s in streams for p in s.split(delim)[:-1]]
            if len(parts) >= 3 and all(parts):
                return Framing(kind="delimiter", delimiter=delim.hex())
    lf = _find_stream_length_field(streams)
    if lf is not None:
        return Framing(kind="length_prefixed", length_field=lf)
    for size in range(2, 65):
        if all(len(s) % size == 0 and len(s) // size >= 3 for s in streams):
            if all(len({s[i] for i in range(0, len(s), size)}) == 1 for s in streams):
                return Framing(kind="fixed", record_size=size)
    return Framing(kind="datagram")


def _find_stream_length_field(streams: list[bytes]) -> LengthField | None:
    for off in range(4):
        for ftype in ("u8", "u16be", "u16le", "u32be", "u32le"):
            width = FIELD_TYPES[ftype][1]
            adjusts = [off + width, 0, off + width + 1, off + width + 2, *list(range(-4, 9))]
            seen: set[int] = set()
            for adjust in adjusts:
                if adjust in seen:
                    continue
                seen.add(adjust)
                lf = LengthField(offset=off, type=ftype, adjust=adjust)
                parts = [split_frames(s, Framing(kind="length_prefixed", length_field=lf)) for s in streams]
                # A zero length value means header-only frames: implausible enough to reject the
                # hypothesis (otherwise "1-byte frames" explain any stream that starts with 0x00).
                plausible = all(read_field(p, off, ftype) for frames in parts for p in frames)
                if plausible and all(len(c) >= 2 for c in parts) and sum(len(c) for c in parts) >= 3:
                    return lf
    return None


def split_frames(stream: bytes, framing: Framing) -> list[bytes]:
    """Split a stream; returns [] if the framing does not consume the stream exactly."""
    if framing.kind == "delimiter" and framing.delimiter:
        delim = bytes.fromhex(framing.delimiter)
        parts = stream.split(delim)
        return list(parts[:-1]) if stream.endswith(delim) else []
    if framing.kind == "fixed" and framing.record_size:
        k = framing.record_size
        if len(stream) % k:
            return []
        return [stream[i : i + k] for i in range(0, len(stream), k)]
    if framing.kind == "length_prefixed" and framing.length_field:
        lf = framing.length_field
        width = FIELD_TYPES[lf.type][1]
        out: list[bytes] = []
        pos = 0
        while pos < len(stream):
            v = read_field(stream, pos + lf.offset, lf.type)
            if v is None:
                return []
            total = v + lf.adjust
            if total < lf.offset + width or pos + total > len(stream):
                return []
            out.append(stream[pos : pos + total])
            pos += total
        return out
    return [stream] if stream else []
