"""Polling coordinator for Modigliani Server devices."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import ModiglianiApi, ModiglianiAuthError, ModiglianiError
from .const import DOMAIN, SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)


@dataclass
class ModiglianiData:
    """Runtime data stored on the config entry."""

    api: ModiglianiApi
    coordinator: ModiglianiCoordinator


type ModiglianiConfigEntry = ConfigEntry[ModiglianiData]


class ModiglianiCoordinator(DataUpdateCoordinator[dict[str, dict[str, Any]]]):
    """Fetches all devices; data maps device id ("profile/key") to the API's device view."""

    config_entry: ModiglianiConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ModiglianiConfigEntry, api: ModiglianiApi) -> None:
        super().__init__(hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=SCAN_INTERVAL)
        self.api = api

    async def _async_update_data(self) -> dict[str, dict[str, Any]]:
        try:
            devices = await self.api.devices()
        except ModiglianiAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except ModiglianiError as err:
            raise UpdateFailed(str(err)) from err
        return {d["id"]: d for d in devices if "id" in d}
