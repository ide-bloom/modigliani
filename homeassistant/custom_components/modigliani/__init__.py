"""The Modigliani integration: devices revived by Modigliani Server, without MQTT."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.const import CONF_DEVICE_ID, CONF_URL, Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType

from .api import ModiglianiApi, ModiglianiError
from .const import ATTR_VALUE, ATTR_VARIABLE, CONF_TOKEN, DOMAIN, SERVICE_SEND_COMMAND
from .coordinator import ModiglianiConfigEntry, ModiglianiCoordinator, ModiglianiData

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.CLIMATE,
    Platform.LIGHT,
    Platform.NUMBER,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)

SEND_COMMAND_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_DEVICE_ID): cv.string,
        vol.Required(ATTR_VARIABLE): cv.string,
        vol.Required(ATTR_VALUE): object,
    }
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the send_command service (once, independent of config entries)."""

    async def send_command(call: ServiceCall) -> None:
        device = dr.async_get(hass).async_get(call.data[CONF_DEVICE_ID])
        if device is None:
            raise ServiceValidationError(f"unknown device {call.data[CONF_DEVICE_ID]}")
        ident = next((i[1] for i in device.identifiers if i[0] == DOMAIN), None)
        if ident is None or "/" not in ident:
            raise ServiceValidationError("not a Modigliani device")
        profile, key = ident.split("/", 1)
        # Home Assistant 2026.10 gave each device a single owning entry (config_entry_id).
        owner = getattr(device, "config_entry_id", None)
        owners = {owner} if owner else set(getattr(device, "config_entries", ()))
        entry: ModiglianiConfigEntry | None = next(
            (e for e in hass.config_entries.async_loaded_entries(DOMAIN) if e.entry_id in owners), None
        )
        if entry is None:
            raise ServiceValidationError("the device's Modigliani server is not loaded")
        value: Any = call.data[ATTR_VALUE]
        try:
            await entry.runtime_data.api.send_command(profile, key, call.data[ATTR_VARIABLE], value)
        except ModiglianiError as err:
            raise HomeAssistantError(f"Modigliani command failed: {err}") from err
        await entry.runtime_data.coordinator.async_request_refresh()

    hass.services.async_register(DOMAIN, SERVICE_SEND_COMMAND, send_command, schema=SEND_COMMAND_SCHEMA)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ModiglianiConfigEntry) -> bool:
    """Set up a Modigliani Server from a config entry."""
    api = ModiglianiApi(async_get_clientsession(hass), entry.data[CONF_URL], entry.data[CONF_TOKEN])
    coordinator = ModiglianiCoordinator(hass, entry, api)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = ModiglianiData(api=api, coordinator=coordinator)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ModiglianiConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
