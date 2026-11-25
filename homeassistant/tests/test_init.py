"""Setup, entities, commands, the send_command service and diagnostics."""

from __future__ import annotations

import json

import pytest
from homeassistant.components.climate import ATTR_HVAC_ACTION, ATTR_HVAC_MODE, HVACAction, HVACMode
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, ATTR_TEMPERATURE
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.modigliani.const import DOMAIN
from custom_components.modigliani.diagnostics import async_get_config_entry_diagnostics

from .conftest import TOKEN, URL


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


def _commands(mock: AiohttpClientMocker) -> list[tuple[str, object]]:
    out = []
    for method, url, data, _headers in mock.mock_calls:
        if method == "POST":
            out.append((str(url).removeprefix(URL), data))
    return out


async def test_entities_are_created(hass: HomeAssistant, server: AiohttpClientMocker, entry: MockConfigEntry) -> None:
    await _setup(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    climate = hass.states.get("climate.thermostat_th_1")
    assert climate is not None
    assert climate.state == HVACMode.HEAT
    assert climate.attributes["current_temperature"] == 20.5
    assert climate.attributes[ATTR_TEMPERATURE] == 21.0
    assert climate.attributes[ATTR_HVAC_ACTION] == HVACAction.HEATING
    assert set(climate.attributes["hvac_modes"]) == {HVACMode.HEAT, HVACMode.COOL}
    assert hass.states.get("sensor.thermostat_th_1_humidity").state == "41"
    assert hass.states.get("switch.plug_sp_1_power").state == "off"
    watts = hass.states.get("sensor.plug_sp_1_watts")
    assert watts.state == "0.0" and watts.attributes["unit_of_measurement"] == "W"
    assert hass.states.get("light.plug_sp_1_led").state == "on"
    assert hass.states.get("binary_sensor.plug_sp_1_led_state").state == "on"
    assert hass.states.get("number.plug_sp_1_level").state == "3.0"
    assert hass.states.get("select.plug_sp_1_fan").state == "low"
    device = dr.async_get(hass).async_get_device_by_identifier((DOMAIN, "thermo/TH-1"), entry.entry_id)
    assert device is not None and device.manufacturer == "Acme" and device.model == "T-200"


async def test_entities_send_commands(hass: HomeAssistant, server: AiohttpClientMocker, entry: MockConfigEntry) -> None:
    await _setup(hass, entry)
    await hass.services.async_call("switch", "turn_on", {ATTR_ENTITY_ID: "switch.plug_sp_1_power"}, blocking=True)
    await hass.services.async_call(
        "climate", "set_temperature", {ATTR_ENTITY_ID: "climate.thermostat_th_1", ATTR_TEMPERATURE: 22.5}, blocking=True
    )
    await hass.services.async_call(
        "climate",
        "set_hvac_mode",
        {ATTR_ENTITY_ID: "climate.thermostat_th_1", ATTR_HVAC_MODE: HVACMode.COOL},
        blocking=True,
    )
    await hass.services.async_call(
        "number", "set_value", {ATTR_ENTITY_ID: "number.plug_sp_1_level", "value": 7}, blocking=True
    )
    await hass.services.async_call(
        "select", "select_option", {ATTR_ENTITY_ID: "select.plug_sp_1_fan", "option": "high"}, blocking=True
    )
    await hass.services.async_call("light", "turn_off", {ATTR_ENTITY_ID: "light.plug_sp_1_led"}, blocking=True)
    assert _commands(server) == [
        ("/api/devices/plug/SP-1/commands", {"variable": "power", "value": True}),
        ("/api/devices/thermo/TH-1/commands", {"variable": "setpoint", "value": 22.5}),
        ("/api/devices/thermo/TH-1/commands", {"variable": "mode", "value": "cool"}),
        ("/api/devices/plug/SP-1/commands", {"variable": "level", "value": 7.0}),
        ("/api/devices/plug/SP-1/commands", {"variable": "fan", "value": "high"}),
        ("/api/devices/plug/SP-1/commands", {"variable": "led", "value": False}),
    ]
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            "climate",
            "set_hvac_mode",
            {ATTR_ENTITY_ID: "climate.thermostat_th_1", ATTR_HVAC_MODE: HVACMode.DRY},
            blocking=True,
        )


async def test_send_command_service(hass: HomeAssistant, server: AiohttpClientMocker, entry: MockConfigEntry) -> None:
    await _setup(hass, entry)
    device = dr.async_get(hass).async_get_device_by_identifier((DOMAIN, "plug/SP-1"), entry.entry_id)
    assert device is not None
    await hass.services.async_call(
        DOMAIN, "send_command", {"device_id": device.id, "variable": "power", "value": "on"}, blocking=True
    )
    assert _commands(server)[-1] == ("/api/devices/plug/SP-1/commands", {"variable": "power", "value": "on"})


async def test_offline_devices_are_unavailable(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, entry: MockConfigEntry, devices: list[dict]
) -> None:
    devices[1]["online"] = False
    aioclient_mock.get(f"{URL}/api/devices", json=devices)
    await _setup(hass, entry)
    assert hass.states.get("switch.plug_sp_1_power").state == "unavailable"


async def test_setup_retries_when_server_is_down(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, entry: MockConfigEntry
) -> None:
    aioclient_mock.get(f"{URL}/api/devices", exc=TimeoutError())
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_diagnostics_are_redacted(
    hass: HomeAssistant, server: AiohttpClientMocker, entry: MockConfigEntry
) -> None:
    await _setup(hass, entry)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    text = json.dumps(diag)
    for secret in (TOKEN, "SP-1", "TH-1", "192.168.1.20"):
        assert secret not in text
    assert diag["devices"][0]["state"]["temp"] == 20.5


async def test_unload(hass: HomeAssistant, server: AiohttpClientMocker, entry: MockConfigEntry) -> None:
    await _setup(hass, entry)
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.NOT_LOADED
