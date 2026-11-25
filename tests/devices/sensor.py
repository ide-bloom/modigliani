"""Sensor: plaintext CoAP over UDP with a binary frame protocol protected by CRC-8.

Frame: A5 | type | len | body (len bytes) | crc8(type..body)
  0x01 telemetry  body = temp(int16 BE, 0.1 °C) humidity(u8) battery(u8) led(u8)
  0x02 config     body = led(u8)              (cloud -> device, in every telemetry answer)
  0x03 hello      body = fw major, fw minor   (registration)
  0x04 hello ack  body = report interval (s)
"""

from __future__ import annotations

import random
import secrets
import socket
import time
from typing import Any

from tests.devices.base import Device
from tests.support.net import Target

DEVICE_ID = "SN4471"
MAGIC = 0xA5
FRAME_TELEMETRY, FRAME_CONFIG, FRAME_HELLO, FRAME_HELLO_ACK = 0x01, 0x02, 0x03, 0x04


def crc8(data: bytes) -> int:
    crc = 0
    for c in data:
        crc ^= c
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def build_frame(ftype: int, body: bytes) -> bytes:
    core = bytes([ftype, len(body)]) + body
    return bytes([MAGIC]) + core + bytes([crc8(core)])


def parse_frame(data: bytes) -> tuple[int, bytes] | None:
    if len(data) < 4 or data[0] != MAGIC or data[2] != len(data) - 4 or crc8(data[1:-1]) != data[-1]:
        return None
    return data[1], data[3:-1]


class Sensor(Device):
    name = "sensor"

    def __init__(self, target: Target, interval: float = 1.0) -> None:
        super().__init__()
        self.target = target
        self.interval = interval
        self.state = {"temperature": 21.7, "humidity": 45, "battery": 97, "led": False}
        self.mid = random.randint(0, 0xFFFF)

    def _request(self, sock: socket.socket, path: str, payload: bytes) -> Any:
        """One confirmable CoAP POST with retransmission; aiocoap does the message encoding."""
        import aiocoap

        self.mid = (self.mid + 1) & 0xFFFF
        msg = aiocoap.Message(code=aiocoap.POST, uri_path=("s", DEVICE_ID, path), payload=payload)
        msg.mtype = aiocoap.CON
        msg.mid = self.mid
        msg.token = secrets.token_bytes(4)
        raw = msg.encode()
        for _ in range(3):
            sock.sendto(raw, (self.target.host, self.target.port))
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                sock.settimeout(max(0.05, deadline - time.monotonic()))
                try:
                    data, _ = sock.recvfrom(2048)
                except TimeoutError:
                    break
                resp = aiocoap.Message.decode(data)
                if resp.mid == msg.mid and resp.token == msg.token:
                    return resp
        raise TimeoutError(f"no answer to POST {path}")

    def run(self) -> None:
        # A plain UDP socket bound to the device's own address: the device's IP is what
        # enrollment keys on, and aiocoap's client transports do not bind source addresses everywhere.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.target.source_ip, 0))
            while not self._stop.is_set():
                try:
                    if not self.health.authenticated:
                        resp = self._request(sock, "hello", build_frame(FRAME_HELLO, bytes([2, 3])))
                        frame = parse_frame(resp.payload)
                        if resp.code.is_successful() and frame and frame[0] == FRAME_HELLO_ACK:
                            self.health.authenticated = True
                        else:
                            self.health.error(f"hello rejected: {resp.code} {resp.payload.hex()}")
                    else:
                        with self.lock:
                            s = self.state
                            s["temperature"] = round(
                                min(26.0, max(18.0, s["temperature"] + random.choice((-0.1, 0.0, 0.1)))), 1
                            )
                            s["humidity"] = max(30, min(70, s["humidity"] + random.choice((-1, 0, 0, 1))))
                            body = round(s["temperature"] * 10).to_bytes(2, "big", signed=True) + bytes(
                                [s["humidity"], s["battery"], 1 if s["led"] else 0]
                            )
                        resp = self._request(sock, "t", build_frame(FRAME_TELEMETRY, body))
                        frame = parse_frame(resp.payload)
                        if resp.code.is_successful() and frame and frame[0] == FRAME_CONFIG:
                            self.health.ok()
                            with self.lock:
                                led = bool(frame[1][0])
                                if led != self.state["led"]:
                                    self.state["led"] = led
                                    self.health.commands_applied += 1
                        else:
                            self.health.error(f"telemetry rejected: {resp.code} {resp.payload.hex()}")
                except (TimeoutError, OSError, ValueError) as exc:
                    self.health.error(f"coap: {exc!r}")
                self.sleep(self.interval)


def readings(sensor: Sensor) -> dict[str, Any]:
    return sensor.snapshot()
