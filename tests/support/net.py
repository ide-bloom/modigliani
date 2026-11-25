"""Networking helpers for simulators: SNI that differs from the connect address, background loops."""

from __future__ import annotations

import asyncio
import http.client
import socket
import ssl
import threading
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Target:
    """Where a simulated device connects (address) and who it believes it talks to (hostname).

    In production the hostname resolves to the vendor or to Modigliani via DNS; in tests the
    address is a localhost port mapping while TLS SNI and the Host header keep the real name.
    """

    host: str
    port: int
    hostname: str
    source_ip: str = "127.0.0.1"


class SniHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: Target, context: ssl.SSLContext, timeout: float = 5.0) -> None:
        super().__init__(target.hostname, target.port, context=context, timeout=timeout)
        self._target = target

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._target.host, self._target.port), self.timeout, source_address=(self._target.source_ip, 0)
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self._target.hostname)  # type: ignore[attr-defined]


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


class LoopThread:
    """Runs an asyncio loop in a daemon thread so simulators can live inside pytest."""

    def __init__(self, name: str) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, name=name, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self, coro: Coroutine[Any, Any, Any], timeout: float = 10.0) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=5)
