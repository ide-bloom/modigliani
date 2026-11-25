"""Thermostat: MQTT 3.1.1 over TLS with JSON telemetry, setpoint/mode commands and time sync.

Its owner can configure which CA it trusts, so it accepts Modigliani's local CA.
"""

from __future__ import annotations

import json
import random
import socket
import ssl
import time
from typing import Any

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion

from tests.devices.base import Device
from tests.support.net import Target

DEVICE_ID = "TH-9F8E7D"
PASSWORD = "thermo-pass-4"


class _SniClient(mqtt.Client):
    """paho connects to `host`; we connect to the mapped address but keep `host` for SNI."""

    def __init__(self, target: Target, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._target = target

    def _create_socket_connection(self) -> socket.socket:
        return socket.create_connection(
            (self._target.host, self._target.port),
            timeout=self._connect_timeout,
            source_address=(self._target.source_ip, 0),
        )


class Thermostat(Device):
    name = "thermostat"

    def __init__(self, target: Target, trust: list[str], telemetry_interval: float = 1.0) -> None:
        super().__init__()
        self.target = target
        self.trust = trust
        self.telemetry_interval = telemetry_interval
        self.state = {"temp": 20.4, "setpoint": 20.0, "mode": "heat", "humidity": 41, "heating": False}
        self.time_synced = 0

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: Any, rc: Any, props: Any = None) -> None:
        if rc.is_failure:
            self.health.error(f"connack {rc}")
            return
        self.health.authenticated = True
        client.subscribe(f"thermo/{DEVICE_ID}/cmd", qos=1)
        client.subscribe(f"thermo/{DEVICE_ID}/time/resp", qos=0)

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: Any) -> None:
        try:
            payload = json.loads(msg.payload)
        except ValueError:
            return
        if msg.topic.endswith("/time/resp"):
            self.time_synced += 1
            return
        with self.lock:
            if isinstance(payload.get("setpoint"), int | float):
                self.state["setpoint"] = float(payload["setpoint"])
                self.health.commands_applied += 1
            if isinstance(payload.get("mode"), str):
                self.state["mode"] = payload["mode"]
                self.health.commands_applied += 1

    def run(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        for ca in self.trust:
            ctx.load_verify_locations(ca)
        client = _SniClient(
            self.target,
            callback_api_version=CallbackAPIVersion.VERSION2,
            client_id=f"thermo-{DEVICE_ID}",
            protocol=mqtt.MQTTv311,
        )
        client.username_pw_set(DEVICE_ID, PASSWORD)
        client.tls_set_context(ctx)
        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.reconnect_delay_set(1, 2)
        while not self._stop.is_set():
            try:
                client.connect(self.target.hostname, self.target.port, keepalive=20)
                break
            except (OSError, ssl.SSLError) as exc:
                self.health.error(f"connect: {exc}")
                self.sleep(1)
        client.loop_start()
        last_time_sync = 0.0
        try:
            while self.sleep(self.telemetry_interval):
                if not client.is_connected():
                    continue
                with self.lock:
                    s = self.state
                    s["heating"] = s["mode"] == "heat" and s["temp"] < s["setpoint"]
                    drift = (
                        0.15 if s["heating"] else (-0.15 if s["mode"] == "cool" and s["temp"] > s["setpoint"] else 0.0)
                    )
                    s["temp"] = round(s["temp"] + drift + random.uniform(-0.05, 0.05), 1)
                    s["humidity"] = max(30, min(60, s["humidity"] + random.choice((-1, 0, 1))))
                    report = dict(s)
                info = client.publish(f"thermo/{DEVICE_ID}/telemetry", json.dumps(report), qos=0)
                if info.rc == mqtt.MQTT_ERR_SUCCESS:
                    self.health.ok()
                if time.time() - last_time_sync > 5:
                    client.publish(f"thermo/{DEVICE_ID}/time/req", json.dumps({"tz": "UTC"}), qos=0)
                    last_time_sync = time.time()
        finally:
            client.loop_stop()
            client.disconnect()
