"""Numbers for writable numeric state variables."""

from __future__ import annotations

from typing import Any

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import ModiglianiConfigEntry
from .entity import ModiglianiEntity, setup_platform_entities

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant, entry: ModiglianiConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    setup_platform_entities(entry, "number", ModiglianiNumber, async_add_entities)


class ModiglianiNumber(ModiglianiEntity, NumberEntity):
    _attr_mode = NumberMode.BOX

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        m = self.mapping
        if m.get("min") is not None:
            self._attr_native_min_value = float(m["min"])
        if m.get("max") is not None:
            self._attr_native_max_value = float(m["max"])
        if m.get("step") is not None:
            self._attr_native_step = float(m["step"])
        self._attr_native_unit_of_measurement = m.get("unit")

    @property
    def native_value(self) -> float | None:
        value = self.variable_value(self.mapping.get("variable"))
        return float(value) if isinstance(value, int | float) else None

    async def async_set_native_value(self, value: float) -> None:
        await self.send(self.mapping["variable"], value)
