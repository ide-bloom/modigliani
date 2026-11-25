"""Selects for writable enum state variables."""

from __future__ import annotations

from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import ModiglianiConfigEntry
from .entity import ModiglianiEntity, setup_platform_entities

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant, entry: ModiglianiConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    setup_platform_entities(entry, "select", ModiglianiSelect, async_add_entities)


class ModiglianiSelect(ModiglianiEntity, SelectEntity):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._attr_options = [str(o) for o in self.mapping.get("options") or []]

    @property
    def current_option(self) -> str | None:
        value = self.variable_value(self.mapping.get("variable"))
        return None if value is None else str(value)

    async def async_select_option(self, option: str) -> None:
        await self.send(self.mapping["variable"], option)
