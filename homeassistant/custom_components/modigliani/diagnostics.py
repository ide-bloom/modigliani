"""Diagnostics with redaction of the token and per-device identifiers."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .const import CONF_TOKEN
from .coordinator import ModiglianiConfigEntry

# Device keys are serial numbers or device IDs, and remote addresses locate the device.
TO_REDACT = {CONF_TOKEN, "key", "id", "remote"}


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ModiglianiConfigEntry) -> dict[str, Any]:
    devices = list(entry.runtime_data.coordinator.data.values())
    return {
        "entry": async_redact_data(dict(entry.data), TO_REDACT),
        "devices": [async_redact_data(d, TO_REDACT) for d in devices],
    }
