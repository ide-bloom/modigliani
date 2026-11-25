"""Common simulator plumbing: a worker thread, observable state and health counters."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Health:
    authenticated: bool = False
    telemetry_ok: int = 0
    commands_applied: int = 0
    errors: list[str] = field(default_factory=list)
    last_ok: float = 0.0

    def ok(self) -> None:
        self.telemetry_ok += 1
        self.last_ok = time.time()

    def error(self, msg: str) -> None:
        self.errors.append(msg)
        del self.errors[:-50]


class Device:
    name = "device"

    def __init__(self) -> None:
        self.state: dict[str, Any] = {}
        self.health = Health()
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.state)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_safe, name=self.name, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _run_safe(self) -> None:
        try:
            self.run()
        except Exception as exc:  # noqa: BLE001 - simulators record every failure for the test to inspect
            self.health.error(f"crashed: {exc!r}")

    def run(self) -> None:
        raise NotImplementedError

    def sleep(self, seconds: float) -> bool:
        """Sleep unless stopped; returns False once the device should stop."""
        return not self._stop.wait(seconds)


def wait_until(predicate: Any, timeout: float = 15.0, interval: float = 0.2) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())
