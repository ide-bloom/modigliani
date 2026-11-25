"""Raw framing and checksum search, frame layouts."""

from __future__ import annotations

import struct

from modigliani.infer import frames as fr
from modigliani.profile.model import Checksum, Frame, FrameField, Framing, LengthField


def test_checksum_vectors() -> None:
    data = b"123456789"
    assert fr.crc8(data) == 0xF4
    assert fr.crc16_ccitt(data) == 0x29B1
    assert fr.crc16_modbus(data) == 0x4B37
    assert fr.crc32(data) == 0xCBF43926
    assert fr.sum8(b"\x01\x02\xff") == 0x02
    assert fr.xor8(b"\x0f\xf0") == 0xFF


def _frame(ftype: int, body: bytes) -> bytes:
    core = bytes([ftype, len(body)]) + body
    return b"\xa5" + core + bytes([fr.crc8(core)])


def test_checksum_search_needs_distinct_frames() -> None:
    frames = [_frame(1, bytes([i, i * 3, 7])) for i in range(5)]
    ck = fr.find_checksum(frames)
    assert ck is not None and (ck.algorithm, ck.start, ck.offset) == ("crc8", 1, -1)
    assert all(fr.verify_checksum(f, ck) for f in frames)
    assert fr.find_checksum([frames[0], frames[0]]) is None


def test_crc16_little_endian_found() -> None:
    frames = []
    for i in range(4):
        body = bytes([0x10, i, i + 7, 0x42])
        frames.append(body + struct.pack("<H", fr.crc16_modbus(body)))
    ck = fr.find_checksum(frames)
    assert ck is not None and ck.algorithm == "crc16_modbus" and ck.endian == "little"


def test_framing_delimiter_length_fixed() -> None:
    assert fr.infer_framing([b"T=21\nH=40\nT=22\n"]).kind == "delimiter"
    stream = b"".join(struct.pack(">H", len(p)) + p for p in (b"abc", b"defgh", b"ij"))
    framing = fr.infer_framing([stream])
    assert framing.kind == "length_prefixed" and framing.length_field is not None
    assert fr.split_frames(stream, framing) == [b"\x00\x03abc", b"\x00\x05defgh", b"\x00\x02ij"]
    fixed = b"".join(bytes([0x7E, i, 0, 0, 1, 2, 9]) for i in range(4))
    f2 = fr.infer_framing([fixed])
    assert f2.kind in ("fixed", "length_prefixed")
    assert fr.infer_framing([b"\x01\x02"]).kind == "datagram"
    assert (
        fr.split_frames(
            b"abc", Framing(kind="length_prefixed", length_field=LengthField(offset=0, type="u8", adjust=0))
        )
        == []
    )


def test_infer_frame_with_hints_and_length_field() -> None:
    frames = []
    temps = [215, 216, 218, 221]
    for i, t in enumerate(temps):
        body = struct.pack(">h", t) + bytes([40 + i, 97, i % 2])
        frames.append((float(i * 10), _frame(1, body)))
    hints = [
        fr.NumericHint(ts=10.5, value=21.6, name="temperature", lo=-15, hi=5),
        fr.NumericHint(ts=9.0, value=1.0, name="led", is_bool=True),
    ]
    ck = fr.find_checksum([f for _, f in frames])
    layout, matches = fr.infer_frame("telemetry", frames, hints, ck)
    by = {f.name: f for f in layout.fields}
    assert (by["temperature"].offset, by["temperature"].type, by["temperature"].scale) == (3, "i16be", 0.1)
    assert by["led"].offset == 7
    assert by["const_0"].const == 0xA5
    assert layout.length_field == LengthField(offset=2, type="u8", adjust=4)
    assert {m.name for m in matches} == {"temperature", "led"}
    decoded = fr.decode_frame(frames[1][1], layout)
    assert decoded["temperature"] == 21.6


def test_encode_frame_fills_length_and_checksum() -> None:
    layout = Frame(
        id="cfg",
        length=5,
        fields=[
            FrameField(name="m", offset=0, type="u8", const=0xA5),
            FrameField(name="t", offset=1, type="u8", const=2),
            FrameField(name="led", offset=3, type="u8"),
        ],
        length_field=LengthField(offset=2, type="u8", adjust=4),
        checksum=Checksum(algorithm="crc8", offset=-1, start=1, end=-1),
    )
    assert fr.encode_frame(layout, {"led": 1}) == _frame(2, b"\x01")
