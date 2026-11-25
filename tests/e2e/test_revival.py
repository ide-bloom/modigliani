"""End-to-end: record, infer, shut the cloud down, revive through Modigliani Server.

Runs on loopback with localhost port mapping; no Wi-Fi, Npcap or real devices are needed.
"""

from __future__ import annotations

import http.client
import json
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt
import pytest
import yaml
from paho.mqtt.enums import CallbackAPIVersion

from tests.devices.base import wait_until
from tests.devices.sensor import DEVICE_ID as SENSOR_ID
from tests.devices.sensor import Sensor
from tests.devices.smartplug import SERIAL, SmartPlug
from tests.devices.thermostat import DEVICE_ID as THERMO_ID
from tests.devices.thermostat import Thermostat
from tests.e2e.conftest import Recording
from tests.e2e.harness import (
    DEVICE_IPS,
    PLUG_HOST,
    SENSOR_HOST,
    THERMO_HOST,
    ServerPorts,
    run_cli,
    write_server_config,
)
from tests.support.mqtt_broker import Broker
from tests.support.net import Target

pytestmark = [pytest.mark.e2e, pytest.mark.timeout(600)]

API_TOKEN = "e2e-local-api-token"


def _profile(rec: Recording, name: str) -> dict[str, Any]:
    data = yaml.safe_load((rec.workspace / "profiles" / "local" / f"{name}.yaml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


@pytest.fixture(scope="module")
def inferred(recording: Recording) -> Recording:
    """Step 2: infer one profile per device."""
    for device in ("plug", "thermostat", "sensor", "hub"):
        out = run_cli(recording.workspace, "infer", recording.capture, "--device", device, "--id", device)
        (recording.workspace / f"infer-{device}.txt").write_text(out.stdout, encoding="utf-8")
    return recording


def test_lockedhub_is_not_revivable(inferred: Recording) -> None:
    out = (inferred.workspace / "infer-hub.txt").read_text(encoding="utf-8")
    assert "not revivable without firmware access" in out.lower()
    hub = _profile(inferred, "hub")
    assert hub["revivability"]["status"] == "not_revivable_without_firmware_access"
    assert hub["tls"]["mode"] == "strict_verification"
    assert hub["handlers"]["http"] == [] and hub["state"] == []
    # Metadata only: hostnames, timing and sizes were kept; no payload was decoded.
    hosts = hub["revivability"]["hosts"]
    assert {h["host"] for h in hosts} == {"hub.lockedhub.example"}
    assert any(h["tls_outcome"] == "rejected_local_ca" for h in hosts)
    assert any(h["tls_outcome"] == "passthrough" and h["bytes_up"] > 0 for h in hosts)
    capture = json.loads((inferred.workspace / "captures" / "lab.mcap.json").read_text(encoding="utf-8"))
    hub_flows = [f for f in capture["flows"] if f["device"] == "hub"]
    assert hub_flows and all(s["data"] is None for f in hub_flows for s in f["segments"])
    # The hub kept working with its real cloud while being recorded (traffic was forwarded).
    assert inferred.hub_tls_failures >= 1
    assert inferred.hub_reports_during_recording > 0


def test_inferred_state_models(inferred: Recording) -> None:
    plug = _profile(inferred, "plug")
    assert {v["name"]: v["writable"] for v in plug["state"]} == {"power": True, "watts": False}
    assert plug["auth"]["token"]["format"] == "hex" and plug["auth"]["token"]["lifetime_s"] == 3600
    assert [c["transport"] for c in plug["commands"]] == ["http_poll"]
    housekeeping = {h["housekeeping"] for h in plug["handlers"]["http"]}
    assert {"time_sync", "firmware_check"} <= housekeeping

    thermo = _profile(inferred, "thermostat")
    assert {v["name"]: v["writable"] for v in thermo["state"]} == {
        "mode": True,
        "setpoint": True,
        "temp": False,
        "humidity": False,
        "heating": False,
    }
    assert {c["name"] for c in thermo["commands"]} == {"set_mode", "set_setpoint"}
    climate = next(e for e in thermo["home_assistant"]["entities"] if e["platform"] == "climate")
    assert climate["target_temperature"] == "setpoint" and climate["current_temperature"] == "temp"
    time_topic = next(t for t in thermo["handlers"]["mqtt"]["topics"] if t["housekeeping"] == "time_sync")
    assert time_topic["payload"] == {"epoch": "{{now.unix}}"}

    sensor = _profile(inferred, "sensor")
    assert {v["name"]: v["writable"] for v in sensor["state"]} == {"led": True, "temperature": False, "humidity": False}
    telemetry = next(f for f in sensor["frames"] if f["id"] == "post_s_t_req")
    temp = next(f for f in telemetry["fields"] if f["name"] == "temperature")
    assert (temp["offset"], temp["type"], temp["scale"]) == (3, "i16be", 0.1)
    assert telemetry["checksum"]["algorithm"] == "crc8"
    assert telemetry["length_field"] == {"offset": 2, "type": "u8", "adjust": 4}


@pytest.mark.parametrize("device", ["plug", "thermostat", "sensor"])
def test_replay_against_server(inferred: Recording, server_bin: Path, device: str) -> None:
    """`modigliani test` replays the device side of the recording against the real server."""
    out = run_cli(
        inferred.workspace,
        "test",
        str(inferred.workspace / "profiles" / "local" / f"{device}.yaml"),
        "--device",
        device,
        "--server-bin",
        str(server_bin),
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "FAIL" not in out.stdout


def _api(port: int, method: str, path: str, body: Any = None) -> tuple[int, Any]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(
        method,
        path,
        body=json.dumps(body) if body is not None else None,
        headers={"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    data = resp.read()
    return resp.status, json.loads(data) if data else None


@dataclass
class Revived:
    ports: ServerPorts
    plug: SmartPlug
    thermostat: Thermostat
    sensor: Sensor
    ha_messages: dict[str, bytes]
    ha_client: mqtt.Client
    server_log: Path

    def device_state(self, profile: str, key: str) -> dict[str, Any]:
        _, dev = _api(self.ports.api, "GET", f"/api/devices/{profile}/{key}")
        return dev["state"] if isinstance(dev, dict) else {}

    def discovery(self, platform: str, slug: str) -> dict[str, Any]:
        for topic, payload in self.ha_messages.items():
            if topic.startswith(f"homeassistant/{platform}/{slug}/") and payload:
                return dict(json.loads(payload))
        raise AssertionError(f"no {platform} discovery for {slug}: {sorted(self.ha_messages)}")


@pytest.fixture(scope="module")
def revived(inferred: Recording, server_bin: Path) -> Iterator[Revived]:
    """Steps 4-5: start Modigliani Server with the inferred profiles; devices talk to it instead."""
    ws = inferred.workspace
    profiles = ws / "serve"
    profiles.mkdir()
    for name in ("plug", "thermostat", "sensor", "hub"):
        shutil.copy(ws / "profiles" / "local" / f"{name}.yaml", profiles)
    ha_broker = Broker("user-ha-broker")
    ha_port = ha_broker.start()
    ports = ServerPorts()
    config = write_server_config(ws, ports, API_TOKEN, ha_port)
    log = ws / "server.log"
    with log.open("wb") as out:
        server = subprocess.Popen(
            [str(server_bin), "--profiles", str(profiles), "--config", str(config)],
            stdout=out,
            stderr=subprocess.STDOUT,
        )
    messages: dict[str, bytes] = {}
    client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id="home-assistant-test")
    client.on_message = lambda _c, _u, m: messages.__setitem__(m.topic, m.payload)
    try:
        assert wait_until(lambda: _health(ports.api), 30), log.read_text(encoding="utf-8", errors="replace")
        client.connect("127.0.0.1", ha_port)
        client.subscribe("homeassistant/#")
        client.subscribe("modigliani/#")
        client.loop_start()
        # Same devices, same identities; DNS (here: port mapping) now points at the server.
        plug = SmartPlug(Target("127.0.0.1", ports.https, PLUG_HOST, DEVICE_IPS["plug"]))
        thermostat = Thermostat(
            Target("127.0.0.1", ports.mqtts, THERMO_HOST, DEVICE_IPS["thermostat"]), [str(ws / "ca" / "ca.crt")]
        )
        sensor = Sensor(Target("127.0.0.1", ports.coap, SENSOR_HOST, DEVICE_IPS["sensor"]))
        for d in (plug, thermostat, sensor):
            d.start()
        yield Revived(ports, plug, thermostat, sensor, messages, client, log)
        for d in (plug, thermostat, sensor):
            d.stop()
    finally:
        client.loop_stop()
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
        ha_broker.stop()


def _health(port: int) -> bool:
    try:
        return _api(port, "GET", "/api/health")[0] == 200
    except OSError:
        return False


def test_devices_authenticate_and_report(revived: Revived) -> None:
    for d in (revived.plug, revived.thermostat, revived.sensor):
        assert wait_until(lambda d=d: d.health.authenticated and d.health.telemetry_ok >= 3, 30), (
            f"{d.name}: {d.health.errors[-5:]}\n{revived.server_log.read_text(encoding='utf-8', errors='replace')[-4000:]}"
        )
    assert wait_until(lambda: "watts" in revived.device_state("plug", SERIAL), 15)
    assert wait_until(lambda: "temp" in revived.device_state("thermostat", THERMO_ID), 15)
    assert wait_until(lambda: "temperature" in revived.device_state("sensor", SENSOR_ID), 15)
    sensor_state = revived.device_state("sensor", SENSOR_ID)
    assert abs(sensor_state["temperature"] - revived.sensor.snapshot()["temperature"]) <= 0.5
    _, devices = _api(revived.ports.api, "GET", "/api/devices")
    assert {d["id"] for d in devices} == {f"plug/{SERIAL}", f"thermostat/{THERMO_ID}", f"sensor/{SENSOR_ID}"}
    assert all(d["online"] for d in devices)
    # Time sync is answered locally; the thermostat keeps receiving it.
    assert wait_until(lambda: revived.thermostat.time_synced >= 1, 15)


def test_commands_through_local_api(revived: Revived) -> None:
    status, res = _api(
        revived.ports.api, "POST", f"/api/devices/plug/{SERIAL}/commands", {"variable": "power", "value": True}
    )
    assert status == 202 and res["status"] == "queued"
    assert wait_until(lambda: revived.plug.snapshot()["power"] is True, 15)
    assert wait_until(lambda: revived.device_state("plug", SERIAL).get("power") is True, 15)

    _api(
        revived.ports.api,
        "POST",
        f"/api/devices/thermostat/{THERMO_ID}/commands",
        {"variable": "setpoint", "value": 21.5},
    )
    assert wait_until(lambda: revived.thermostat.snapshot()["setpoint"] == 21.5, 15)
    _api(
        revived.ports.api,
        "POST",
        f"/api/devices/thermostat/{THERMO_ID}/commands",
        {"command": "set_mode", "value": "cool"},
    )
    assert wait_until(lambda: revived.thermostat.snapshot()["mode"] == "cool", 15)

    _api(revived.ports.api, "POST", f"/api/devices/sensor/{SENSOR_ID}/commands", {"variable": "led", "value": True})
    assert wait_until(lambda: revived.sensor.snapshot()["led"] is True, 15)

    # Validation: out-of-range values and unknown devices are rejected.
    assert (
        _api(
            revived.ports.api,
            "POST",
            f"/api/devices/thermostat/{THERMO_ID}/commands",
            {"variable": "setpoint", "value": 99},
        )[0]
        == 400
    )
    assert (
        _api(revived.ports.api, "POST", "/api/devices/plug/nope/commands", {"variable": "power", "value": True})[0]
        == 404
    )
    conn = http.client.HTTPConnection("127.0.0.1", revived.ports.api, timeout=5)
    conn.request("GET", "/api/devices")
    assert conn.getresponse().status == 401


def test_commands_through_home_assistant_discovery(revived: Revived) -> None:
    plug_slug, thermo_slug, sensor_slug = "plug_sp_1a2b3c", "thermostat_th_9f8e7d", "sensor_sn4471"
    assert wait_until(lambda: any(t.startswith("homeassistant/climate/") for t in revived.ha_messages), 20)
    switch = revived.discovery("switch", plug_slug)
    climate = revived.discovery("climate", thermo_slug)
    led = revived.discovery("switch", sensor_slug)
    temp_sensor = revived.discovery("sensor", sensor_slug)
    assert switch["unique_id"].startswith("modigliani_") and switch["device"]["identifiers"]
    assert set(climate["modes"]) == {"cool", "heat"}
    assert temp_sensor["device_class"] in ("temperature", "humidity")

    revived.ha_client.publish(switch["command_topic"], "OFF")
    assert wait_until(lambda: revived.plug.snapshot()["power"] is False, 15)
    revived.ha_client.publish(climate["temperature_command_topic"], "23")
    assert wait_until(lambda: revived.thermostat.snapshot()["setpoint"] == 23.0, 15)
    revived.ha_client.publish(climate["mode_command_topic"], "heat")
    assert wait_until(lambda: revived.thermostat.snapshot()["mode"] == "heat", 15)
    revived.ha_client.publish(led["command_topic"], "OFF")
    assert wait_until(lambda: revived.sensor.snapshot()["led"] is False, 15)

    # State flows back to Home Assistant on the entities' state topics.
    def thermo_state() -> dict[str, Any]:
        raw = revived.ha_messages.get(climate["temperature_state_topic"], b"{}")
        return dict(json.loads(raw))

    assert wait_until(lambda: thermo_state().get("setpoint") == 23 and thermo_state().get("__hvac_mode") == "heat", 15)
    assert revived.ha_messages.get("modigliani/status") == b"online"


def test_shared_profiles_contain_no_identifiers(inferred: Recording) -> None:
    ws = inferred.workspace
    secrets = ["SP-1A2B3C", "TH-9F8E7D", "SN4471", "factory-pass-7", "thermo-pass-4", "127.0.0.2", "127.0.0.3"]
    for device in ("plug", "thermostat", "sensor"):
        run_cli(
            ws,
            "export",
            str(ws / "profiles" / "local" / f"{device}.yaml"),
            "--share",
            "--yes",
            "--out",
            str(ws / "shared"),
            "--license",
            "CC0-1.0",
        )
        shared = ws / "shared" / f"{device}.yaml"
        text = shared.read_text(encoding="utf-8")
        for s in secrets:
            assert s.lower() not in text.lower(), f"{s} survived scrubbing in {device}"
        assert (ws / "shared" / f"{device}.yaml.sig").exists()
        verify = run_cli(ws, "verify", str(shared))
        assert "signature: valid" in verify.stdout
        # Install fills placeholders back in from the installer's own capture.
        run_cli(ws, "install", str(shared), inferred.capture, "--device", device)
    installed = yaml.safe_load((ws / "profiles" / "local" / "plug.yaml").read_text(encoding="utf-8"))
    assert "SP-1A2B3C" in json.dumps(installed["placeholders"])
