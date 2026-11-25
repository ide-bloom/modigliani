"""Vendor cloud for the Thermostat: an MQTT-over-TLS broker plus the vendor's cloud logic."""

from __future__ import annotations

import json
import ssl
import time
from typing import Any

from tests.support.mqtt_broker import Broker, Session
from tests.support.pki import ServerCert


class ThermostatCloud:
    def __init__(self, cert: ServerCert) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert.cert, cert.key)
        self.broker = Broker("thermostat-cloud", tls=ctx)
        self.broker.hooks.append(self._on_publish)
        self.telemetry: dict[str, dict[str, Any]] = {}
        self.port = 0

    def _on_publish(self, session: Session, topic: str, payload: bytes) -> None:
        parts = topic.split("/")
        if len(parts) == 4 and parts[0] == "thermo" and parts[2:] == ["time", "req"]:
            self.broker.publish(f"thermo/{parts[1]}/time/resp", json.dumps({"epoch": int(time.time())}).encode())
        elif len(parts) == 3 and parts[0] == "thermo" and parts[2] == "telemetry":
            self.telemetry[parts[1]] = json.loads(payload)

    # ------------------------------------------------------------------ the vendor phone app

    def app_set_setpoint(self, device_id: str, value: float) -> None:
        self.broker.publish(f"thermo/{device_id}/cmd", json.dumps({"setpoint": value}).encode(), qos=1)

    def app_set_mode(self, device_id: str, mode: str) -> None:
        self.broker.publish(f"thermo/{device_id}/cmd", json.dumps({"mode": mode}).encode(), qos=1)

    def start(self) -> int:
        self.port = self.broker.start()
        return self.port

    def stop(self) -> None:
        self.broker.stop()
