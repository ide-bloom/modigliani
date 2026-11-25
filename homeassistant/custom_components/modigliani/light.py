"""On/off lights for writable state variables named like lights."""

from __future__ import annotations

from typing import Any

from homeassistant.components.light import ColorMode, LightEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import ModiglianiConfigEntry
from .entity import ModiglianiEntity, setup_platform_entities

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant, entry: ModiglianiConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    setup_platform_entities(entry, "light", ModiglianiLight, async_add_entities)


class ModiglianiLight(ModiglianiEntity, LightEntity):
    _attr_color_mode = ColorMode.ONOFF

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._attr_supported_color_modes = {ColorMode.ONOFF}

    @property
    def is_on(self) -> bool | None:
        value = self.variable_value(self.mapping.get("variable"))
        return None if value is None else bool(value)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.send(self.mapping["variable"], True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.send(self.mapping["variable"], False)
