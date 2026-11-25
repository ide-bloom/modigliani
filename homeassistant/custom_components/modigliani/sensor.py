"""Sensors for read-only numeric and enum state variables."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.const import UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import ModiglianiConfigEntry
from .entity import ModiglianiEntity, setup_platform_entities

PARALLEL_UPDATES = 0
_UNITS = {"°C": UnitOfTemperature.CELSIUS, "°F": UnitOfTemperature.FAHRENHEIT}


async def async_setup_entry(
    hass: HomeAssistant, entry: ModiglianiConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    setup_platform_entities(entry, "sensor", ModiglianiSensor, async_add_entities)


class ModiglianiSensor(ModiglianiEntity, SensorEntity):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        m = self.mapping
        if m.get("device_class") in {c.value for c in SensorDeviceClass}:
            self._attr_device_class = SensorDeviceClass(m["device_class"])
        if m.get("state_class") in {c.value for c in SensorStateClass}:
            self._attr_state_class = SensorStateClass(m["state_class"])
        if m.get("unit"):
            self._attr_native_unit_of_measurement = _UNITS.get(m["unit"], m["unit"])
        if m.get("options"):
            self._attr_options = [str(o) for o in m["options"]]

    @property
    def native_value(self) -> Any:
        return self.variable_value(self.mapping.get("variable"))
