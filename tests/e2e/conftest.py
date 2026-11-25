"""Fixtures for the end-to-end suite (Section 10 of the design: record, infer, shut down, revive)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.devices.lockedhub import LockedHub
from tests.devices.sensor import DEVICE_ID as SENSOR_ID
from tests.devices.sensor import Sensor
from tests.devices.smartplug import SERIAL, SmartPlug
from tests.devices.thermostat import DEVICE_ID as THERMO_ID
from tests.devices.thermostat import Thermostat
from tests.e2e.harness import (
    DEVICE_IPS,
    HUB_HOST,
    PLUG_HOST,
    REPO,
    SENSOR_HOST,
    THERMO_HOST,
    Clouds,
    ProxyPorts,
    run_cli,
    start_cli,
    wait_file,
)
from tests.support.net import Target


@pytest.fixture(scope="session")
def server_bin() -> Iterator[Path]:
    """The Go server, built fresh into a temporary directory (never into the repository)."""
    env = os.environ.get("MODIGLIANI_SERVER_BIN")
    if env:
        yield Path(env)
        return
    if shutil.which("go") is None:
        pytest.skip("Go toolchain not found and MODIGLIANI_SERVER_BIN not set")
    out = Path(tempfile.mkdtemp(prefix="modigliani-bin-"))
    exe = out / ("modigliani-server.exe" if os.name == "nt" else "modigliani-server")
    subprocess.run(["go", "build", "-o", str(exe), "./cmd/modigliani-server"], cwd=REPO / "server", check=True)
    yield exe
    shutil.rmtree(out, ignore_errors=True)


@dataclass
class Recording:
    workspace: Path
    clouds_dir: Path
    capture: str
    vendor_ca: Path
    hub_tls_failures: int
    hub_reports_during_recording: int


def _annotate(ws: Path, label: str, device: str) -> None:
    # No capture name: annotate attaches to the capture being recorded.
    run_cli(ws, "annotate", "--add", label, "--at", repr(time.time()), "--device", device)


@pytest.fixture(scope="module")
def recording(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Recording]:
    """Step 1: record every device talking to its cloud through proxy mode, with annotations."""
    ws = tmp_path_factory.mktemp("lab")
    clouds = Clouds.start(ws / "vendor")
    try:
        for name, ip in DEVICE_IPS.items():
            run_cli(ws, "enroll", "--name", name, "--ip", ip, "--i-own-this-device")
        run_cli(ws, "ca", "init")
        ports = ProxyPorts()
        args = [
            "record",
            "--mode",
            "proxy",
            "--name",
            "lab",
            "--minutes",
            "10",
            "--stop-file",
            str(ws / "stop"),
            "--ready-file",
            str(ws / "ready"),
            "--upstream-ca",
            str(clouds.pki.ca_cert),
        ]
        for r in ports.routes(clouds):
            args += ["--route", r]
        log = ws / "record.log"
        proc = start_cli(ws, log, *args)
        wait_file(ws / "ready", 90, proc, log)
        trust = [str(clouds.pki.ca_cert), str(ws / "ca" / "ca.crt")]
        devices = [
            SmartPlug(Target("127.0.0.1", ports.plug, PLUG_HOST, DEVICE_IPS["plug"])),
            Thermostat(Target("127.0.0.1", ports.thermostat, THERMO_HOST, DEVICE_IPS["thermostat"]), trust),
            Sensor(Target("127.0.0.1", ports.sensor, SENSOR_HOST, DEVICE_IPS["sensor"])),
            LockedHub(Target("127.0.0.1", ports.hub, HUB_HOST, DEVICE_IPS["hub"]), str(clouds.pki.ca_cert)),
        ]
        for d in devices:
            d.start()
        time.sleep(3)

        # The "vendor phone app" actions, each annotated the moment it is performed.
        def plug_actions() -> None:
            for value, label in ((True, "turned on"), (False, "turned off"), (True, "turned on")):
                clouds.plug.app_set_power(SERIAL, value)
                _annotate(ws, label, "plug")
                time.sleep(3)

        def thermostat_actions() -> None:
            steps = (
                (lambda: clouds.thermostat.app_set_setpoint(THERMO_ID, 22.5), "set 22.5 C"),
                (lambda: clouds.thermostat.app_set_mode(THERMO_ID, "cool"), "mode cool"),
                (lambda: clouds.thermostat.app_set_setpoint(THERMO_ID, 19.0), "set 19 C"),
                (lambda: clouds.thermostat.app_set_mode(THERMO_ID, "heat"), "mode heat"),
            )
            for action, label in steps:
                action()
                _annotate(ws, label, "thermostat")
                time.sleep(3)

        def sensor_actions() -> None:
            for led in (True, False):
                clouds.sensor.app_set_led(SENSOR_ID, led)
                _annotate(ws, "led on" if led else "led off", "sensor")
                time.sleep(3)
                reading = clouds.sensor.readings[SENSOR_ID]
                _annotate(ws, f"app shows temperature {reading['temperature']} C", "sensor")
                _annotate(ws, f"app shows humidity {reading['humidity']} %", "sensor")
                time.sleep(1)

        workers = [threading.Thread(target=f) for f in (plug_actions, thermostat_actions, sensor_actions)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        time.sleep(2)
        hub = devices[3]
        assert isinstance(hub, LockedHub)
        for d in devices[:3]:
            assert d.health.authenticated, f"{d.name} never authenticated with its cloud: {d.health.errors[-3:]}"
            assert d.health.commands_applied >= 2, f"{d.name} did not obey the vendor app"
        (ws / "stop").write_text("stop", encoding="utf-8")
        assert proc.wait(timeout=90) == 0, log.read_text(encoding="utf-8", errors="replace")
        for d in devices:
            d.stop()
        yield Recording(ws, ws / "vendor", "lab", clouds.pki.ca_cert, hub.tls_failures, clouds.hub.reports)
    finally:
        # Step 3: shut every cloud simulator down. Nothing below may reach a vendor.
        clouds.stop()
