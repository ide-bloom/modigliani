"""Base entity for Modigliani devices."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from homeassistant.core import callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import ModiglianiError
from .const import DOMAIN
from .coordinator import ModiglianiConfigEntry, ModiglianiCoordinator


class ModiglianiEntity(CoordinatorEntity[ModiglianiCoordinator]):
    """An entity created from one entry of a profile's Home Assistant mapping."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: ModiglianiCoordinator, device_id: str, mapping: dict[str, Any]) -> None:
        super().__init__(coordinator)
        self.device_id = device_id
        self.mapping = mapping
        device = coordinator.data[device_id]
        self._attr_unique_id = f"{device_id}/{mapping['key']}"
        self._attr_name = None if mapping["platform"] == "climate" else mapping.get("name")
        vendor = device.get("vendor")
        model = device.get("model")
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_id)},
            name=f"{device.get('name', device['profile'])} {device['key']}",
            manufacturer=vendor if vendor and vendor != "unknown" else None,
            model=model if model and model != "unknown" else None,
        )

    @property
    def device(self) -> dict[str, Any]:
        return self.coordinator.data.get(self.device_id, {})

    @property
    def state_values(self) -> dict[str, Any]:
        state = self.device.get("state")
        return state if isinstance(state, dict) else {}

    def variable_value(self, variable: str | None) -> Any:
        return self.state_values.get(variable) if variable else None

    @property
    def available(self) -> bool:
        return super().available and bool(self.device.get("online"))

    async def send(self, variable: str, value: Any) -> None:
        device = self.device
        try:
            await self.coordinator.api.send_command(device["profile"], device["key"], variable, value)
        except ModiglianiError as err:
            raise HomeAssistantError(f"Modigliani command failed: {err}") from err
        # Optimistically show the requested value until the device reports it.
        device.setdefault("state", {})[variable] = value
        self.async_write_ha_state()
        await self.coordinator.async_request_refresh()


def setup_platform_entities(
    entry: ModiglianiConfigEntry,
    platform: str,
    factory: Callable[[ModiglianiCoordinator, str, dict[str, Any]], Entity],
    add: Callable[[Iterable[Entity]], None],
) -> None:
    """Create entities for every device mapping of a platform, including devices that appear later."""
    coordinator = entry.runtime_data.coordinator
    known: set[str] = set()

    @callback
    def discover() -> None:
        new: list[Entity] = []
        for device_id, device in coordinator.data.items():
            for mapping in device.get("entities") or []:
                if mapping.get("platform") != platform:
                    continue
                uid = f"{device_id}/{mapping['key']}"
                if uid not in known:
                    known.add(uid)
                    new.append(factory(coordinator, device_id, mapping))
        if new:
            add(new)

    discover()
    entry.async_on_unload(coordinator.async_add_listener(discover))
