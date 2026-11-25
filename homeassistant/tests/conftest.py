"""Fixtures for the Modigliani integration tests."""

from __future__ import annotations

from typing import Any

import pytest
from homeassistant.const import CONF_URL
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.modigliani.const import CONF_TOKEN, DOMAIN

URL = "http://modigliani.local:8080"
TOKEN = "test-api-token"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Load integrations from custom_components in every test."""


def thermostat() -> dict[str, Any]:
    return {
        "id": "thermo/TH-1",
        "profile": "thermo",
        "key": "TH-1",
        "name": "Thermostat",
        "vendor": "Acme",
        "model": "T-200",
        "online": True,
        "remote": "192.168.1.30",
        "state": {"temp": 20.5, "setpoint": 21.0, "mode": "heat", "heating": True, "humidity": 41},
        "entities": [
            {
                "platform": "climate",
                "key": "climate",
                "name": "Thermostat",
                "current_temperature": "temp",
                "target_temperature": "setpoint",
                "hvac_mode": "mode",
                "hvac_mode_map": {"heat": "heat", "cool": "cool"},
                "hvac_action": "heating",
                "min": 5,
                "max": 35,
                "step": 0.5,
                "unit": "°C",
            },
            {
                "platform": "sensor",
                "key": "humidity",
                "name": "Humidity",
                "variable": "humidity",
                "unit": "%",
                "device_class": "humidity",
                "state_class": "measurement",
            },
        ],
    }


def plug() -> dict[str, Any]:
    return {
        "id": "plug/SP-1",
        "profile": "plug",
        "key": "SP-1",
        "name": "Plug",
        "vendor": "unknown",
        "model": "unknown",
        "online": True,
        "remote": "192.168.1.20",
        "state": {"power": False, "watts": 0.0, "led": True, "level": 3, "fan": "low"},
        "entities": [
            {"platform": "switch", "key": "power", "name": "Power", "variable": "power"},
            {
                "platform": "sensor",
                "key": "watts",
                "name": "Watts",
                "variable": "watts",
                "unit": "W",
                "device_class": "power",
            },
            {"platform": "light", "key": "led", "name": "LED", "variable": "led"},
            {"platform": "binary_sensor", "key": "led_state", "name": "LED state", "variable": "led"},
            {
                "platform": "number",
                "key": "level",
                "name": "Level",
                "variable": "level",
                "min": 0,
                "max": 10,
                "step": 1,
            },
            {"platform": "select", "key": "fan", "name": "Fan", "variable": "fan", "options": ["low", "high"]},
        ],
    }


@pytest.fixture
def devices() -> list[dict[str, Any]]:
    return [thermostat(), plug()]


@pytest.fixture
def server(aioclient_mock: AiohttpClientMocker, devices: list[dict[str, Any]]) -> AiohttpClientMocker:
    aioclient_mock.get(f"{URL}/api/devices", json=devices)
    for d in devices:
        aioclient_mock.post(
            f"{URL}/api/devices/{d['profile']}/{d['key']}/commands", json={"status": "queued"}, status=202
        )
    return aioclient_mock


@pytest.fixture
def entry() -> MockConfigEntry:
    return MockConfigEntry(domain=DOMAIN, title=URL, unique_id=URL, data={CONF_URL: URL, CONF_TOKEN: TOKEN})
