"""Vendor cloud for the Sensor: plaintext CoAP over UDP carrying binary frames with a CRC-8."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

from modigliani.infer.decoders import CoapMessage, decode_coap, encode_coap
from tests.devices.sensor import FRAME_CONFIG, FRAME_HELLO_ACK, build_frame, parse_frame
from tests.support.net import LoopThread

CHANGED, CREATED, NOT_FOUND = 0x44, 0x41, 0x84


class SensorCloud:
    def __init__(self) -> None:
        self.loop = LoopThread("sensor-cloud")
        self.transport: asyncio.DatagramTransport | None = None
        self.desired_led: dict[str, int] = {}
        self.readings: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.port = 0

    def app_set_led(self, device_id: str, on: bool) -> None:
        with self.lock:
            self.desired_led[device_id] = 1 if on else 0

    def handle(self, data: bytes) -> bytes | None:
        try:
            req = decode_coap(data)
        except ValueError:
            return None
        segs = req.path.strip("/").split("/")
        code, payload = NOT_FOUND, b""
        if req.method == "POST" and len(segs) == 3 and segs[0] == "s":
            device_id = segs[1]
            frame = parse_frame(req.payload)
            if segs[2] == "hello" and frame is not None:
                code, payload = CREATED, build_frame(FRAME_HELLO_ACK, bytes([1]))
            elif segs[2] == "t" and frame is not None:
                _, body = frame
                temp = int.from_bytes(body[0:2], "big", signed=True) / 10
                with self.lock:
                    self.readings[device_id] = {
                        "temperature": temp,
                        "humidity": body[2],
                        "battery": body[3],
                        "led": body[4],
                    }
                    led = self.desired_led.setdefault(device_id, body[4])
                code, payload = CHANGED, build_frame(FRAME_CONFIG, bytes([led]))
        mtype = "ACK" if req.mtype == "CON" else "NON"
        return encode_coap(CoapMessage(mtype, code, req.mid, req.token, [], payload))

    def start(self) -> int:
        cloud = self

        class Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                assert isinstance(transport, asyncio.DatagramTransport)
                cloud.transport = transport

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                reply = cloud.handle(data)
                if reply is not None and cloud.transport is not None:
                    cloud.transport.sendto(reply, addr)

        async def go() -> int:
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Proto, local_addr=("127.0.0.1", 0))
            return int(transport.get_extra_info("sockname")[1])

        self.port = self.loop.run(go())
        return self.port

    def stop(self) -> None:
        if self.transport is not None:
            self.loop.loop.call_soon_threadsafe(self.transport.close)
        self.loop.stop()
