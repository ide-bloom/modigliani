"""Binary sensors for read-only on/off state variables."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import ModiglianiConfigEntry
from .entity import ModiglianiEntity, setup_platform_entities

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant, entry: ModiglianiConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    setup_platform_entities(entry, "binary_sensor", ModiglianiBinarySensor, async_add_entities)


class ModiglianiBinarySensor(ModiglianiEntity, BinarySensorEntity):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        dc = self.mapping.get("device_class")
        if dc in {c.value for c in BinarySensorDeviceClass}:
            self._attr_device_class = BinarySensorDeviceClass(dc)

    @property
    def is_on(self) -> bool | None:
        value = self.variable_value(self.mapping.get("variable"))
        return None if value is None else bool(value)
