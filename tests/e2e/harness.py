"""End-to-end harness: vendor clouds, simulated devices, the Studio CLI and the server.

Everything runs on loopback with localhost port mapping. Each simulated device gets its own
loopback source address (127.0.0.2-5) so enrollment by IP behaves as on a real hotspot.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tests.clouds.lockedhub_cloud import LockedHubCloud
from tests.clouds.sensor_cloud import SensorCloud
from tests.clouds.smartplug_cloud import SmartPlugCloud
from tests.clouds.thermostat_cloud import ThermostatCloud
from tests.support.net import free_port
from tests.support.pki import VendorPki, make_vendor_pki

REPO = Path(__file__).resolve().parents[2]

PLUG_HOST, THERMO_HOST, SENSOR_HOST, HUB_HOST = (
    "api.smartplug.example",
    "mqtt.thermo.example",
    "coap.sensor.example",
    "hub.lockedhub.example",
)
DEVICE_IPS = {"plug": "127.0.0.2", "thermostat": "127.0.0.3", "sensor": "127.0.0.4", "hub": "127.0.0.5"}


def run_cli(workspace: Path, *args: str, timeout: float = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = dict(
        os.environ,
        MODIGLIANI_HOME=str(workspace),
        MODIGLIANI_CONFIG_DIR=str(workspace / "userconfig"),
        PYTHONIOENCODING="utf-8",
        COLUMNS="200",
    )
    proc = subprocess.run(
        [sys.executable, "-m", "modigliani", *args],
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        encoding="utf-8",
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"modigliani {' '.join(args)} failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    return proc


def start_cli(workspace: Path, log: Path, *args: str) -> subprocess.Popen[bytes]:
    """Start a long-running CLI command; output goes to a file so a full pipe can never block it."""
    env = dict(
        os.environ,
        MODIGLIANI_HOME=str(workspace),
        MODIGLIANI_CONFIG_DIR=str(workspace / "userconfig"),
        PYTHONIOENCODING="utf-8",
        COLUMNS="200",
    )
    out = log.open("wb")
    return subprocess.Popen(
        [sys.executable, "-m", "modigliani", *args], cwd=workspace, env=env, stdout=out, stderr=subprocess.STDOUT
    )


def wait_file(
    path: Path, timeout: float = 60.0, proc: subprocess.Popen[bytes] | None = None, log: Path | None = None
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        if proc is not None and proc.poll() is not None:
            text = log.read_text(encoding="utf-8", errors="replace") if log else ""
            raise AssertionError(f"process exited early ({proc.returncode}):\n{text}")
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {path}")


@dataclass
class Clouds:
    pki: VendorPki
    plug: SmartPlugCloud
    thermostat: ThermostatCloud
    sensor: SensorCloud
    hub: LockedHubCloud

    @classmethod
    def start(cls, directory: Path) -> Clouds:
        pki = make_vendor_pki(directory)
        clouds = cls(
            pki,
            SmartPlugCloud(pki.issue("plug", [PLUG_HOST])),
            ThermostatCloud(pki.issue("thermostat", [THERMO_HOST])),
            SensorCloud(),
            LockedHubCloud(pki.issue("hub", [HUB_HOST])),
        )
        for c in (clouds.plug, clouds.thermostat, clouds.sensor, clouds.hub):
            c.start()
        return clouds

    def stop(self) -> None:
        for c in (self.plug, self.thermostat, self.sensor, self.hub):
            c.stop()


@dataclass
class ProxyPorts:
    plug: int = field(default_factory=free_port)
    thermostat: int = field(default_factory=free_port)
    sensor: int = 0
    hub: int = field(default_factory=free_port)

    def __post_init__(self) -> None:
        import socket

        self.sensor = free_port(socket.SOCK_DGRAM)

    def routes(self, clouds: Clouds) -> list[str]:
        return [
            f"https:127.0.0.1:{self.plug}={PLUG_HOST}@127.0.0.1:{clouds.plug.port}",
            f"tls:127.0.0.1:{self.thermostat}={THERMO_HOST}@127.0.0.1:{clouds.thermostat.port}",
            f"udp:127.0.0.1:{self.sensor}={SENSOR_HOST}@127.0.0.1:{clouds.sensor.port}",
            f"https:127.0.0.1:{self.hub}={HUB_HOST}@127.0.0.1:{clouds.hub.port}",
        ]


@dataclass
class ServerPorts:
    http: int = field(default_factory=free_port)
    https: int = field(default_factory=free_port)
    mqtts: int = field(default_factory=free_port)
    coap: int = 0
    api: int = field(default_factory=free_port)

    def __post_init__(self) -> None:
        import socket

        self.coap = free_port(socket.SOCK_DGRAM)


def server_binary() -> Path:
    env = os.environ.get("MODIGLIANI_SERVER_BIN")
    if env and Path(env).exists():
        return Path(env)
    exe = "modigliani-server.exe" if os.name == "nt" else "modigliani-server"
    return REPO / "bin" / exe


def write_server_config(workspace: Path, ports: ServerPorts, token: str, ha_broker_port: int | None) -> Path:
    config: dict[str, Any] = {
        "data_dir": str(workspace / "server-data"),
        "ca_dir": str(workspace / "ca"),
        "api": {"listen": f"127.0.0.1:{ports.api}", "token": token},
        "http": {"listen": [f"127.0.0.1:{ports.http}"], "tls_listen": [f"127.0.0.1:{ports.https}"]},
        "mqtt": {"tls_listen": [f"127.0.0.1:{ports.mqtts}"]},
        "coap": {"listen": [f"127.0.0.1:{ports.coap}"]},
        "enrolled": [{"name": n, "ip": ip} for n, ip in DEVICE_IPS.items()],
        "log_level": "info",
    }
    if ha_broker_port is not None:
        config["home_assistant"] = {"broker": f"tcp://127.0.0.1:{ha_broker_port}", "discovery_prefix": "homeassistant"}
    path = workspace / "server.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path
