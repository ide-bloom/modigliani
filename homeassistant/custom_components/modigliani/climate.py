"""Climate entities for thermostats (target temperature, HVAC mode, current temperature)."""

from __future__ import annotations

from typing import Any

from homeassistant.components.climate import ClimateEntity, ClimateEntityFeature, HVACAction, HVACMode
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import ModiglianiConfigEntry
from .entity import ModiglianiEntity, setup_platform_entities

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant, entry: ModiglianiConfigEntry, async_add_entities: AddConfigEntryEntitiesCallback
) -> None:
    setup_platform_entities(entry, "climate", ModiglianiClimate, async_add_entities)


class ModiglianiClimate(ModiglianiEntity, ClimateEntity):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        m = self.mapping
        unit = m.get("unit") or "°C"
        self._attr_temperature_unit = UnitOfTemperature.FAHRENHEIT if "F" in unit else UnitOfTemperature.CELSIUS
        # device value -> Home Assistant mode, as inferred into the profile
        valid = {mode.value for mode in HVACMode}
        self._mode_map: dict[str, HVACMode] = {
            str(k): HVACMode(v) for k, v in (m.get("hvac_mode_map") or {}).items() if v in valid
        }
        features = ClimateEntityFeature(0)
        if m.get("target_temperature"):
            features |= ClimateEntityFeature.TARGET_TEMPERATURE
        self._attr_supported_features = features
        self._attr_hvac_modes = sorted(set(self._mode_map.values())) or [HVACMode.HEAT]
        if m.get("min") is not None:
            self._attr_min_temp = float(m["min"])
        if m.get("max") is not None:
            self._attr_max_temp = float(m["max"])
        if m.get("step") is not None:
            self._attr_target_temperature_step = float(m["step"])

    @property
    def current_temperature(self) -> float | None:
        v = self.variable_value(self.mapping.get("current_temperature"))
        return float(v) if isinstance(v, int | float) else None

    @property
    def target_temperature(self) -> float | None:
        v = self.variable_value(self.mapping.get("target_temperature"))
        return float(v) if isinstance(v, int | float) else None

    @property
    def hvac_mode(self) -> HVACMode | None:
        if not self._mode_map:
            return HVACMode.HEAT
        v = self.variable_value(self.mapping.get("hvac_mode"))
        return self._mode_map.get(str(v)) if v is not None else None

    @property
    def hvac_action(self) -> HVACAction | None:
        variable = self.mapping.get("hvac_action")
        if not variable:
            return None
        if not self.variable_value(variable):
            return HVACAction.IDLE
        return HVACAction.COOLING if self.hvac_mode == HVACMode.COOL else HVACAction.HEATING

    async def async_set_temperature(self, **kwargs: Any) -> None:
        if (temp := kwargs.get(ATTR_TEMPERATURE)) is not None and self.mapping.get("target_temperature"):
            await self.send(self.mapping["target_temperature"], temp)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        for device_value, mode in self._mode_map.items():
            if mode == hvac_mode and self.mapping.get("hvac_mode"):
                await self.send(self.mapping["hvac_mode"], device_value)
                return
        raise ServiceValidationError(f"{hvac_mode} is not supported by this device")
