"""Config flow: the server URL and its local API token."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_URL
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import ModiglianiApi, ModiglianiAuthError, ModiglianiError
from .const import CONF_TOKEN, DEFAULT_URL, DOMAIN


class ModiglianiConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Modigliani."""

    VERSION = 1

    async def _validate(self, url: str, token: str) -> str | None:
        api = ModiglianiApi(async_get_clientsession(self.hass), url, token)
        try:
            await api.devices()
        except ModiglianiAuthError:
            return "invalid_auth"
        except ModiglianiError:
            return "cannot_connect"
        return None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            url = user_input[CONF_URL].rstrip("/")
            await self.async_set_unique_id(url)
            self._abort_if_unique_id_configured()
            if (error := await self._validate(url, user_input[CONF_TOKEN])) is None:
                return self.async_create_entry(title=url, data={CONF_URL: url, CONF_TOKEN: user_input[CONF_TOKEN]})
            errors["base"] = error
        schema = vol.Schema(
            {
                vol.Required(CONF_URL, default=(user_input or {}).get(CONF_URL, DEFAULT_URL)): str,
                vol.Required(CONF_TOKEN): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            if (error := await self._validate(entry.data[CONF_URL], user_input[CONF_TOKEN])) is None:
                return self.async_update_reload_and_abort(entry, data_updates={CONF_TOKEN: user_input[CONF_TOKEN]})
            errors["base"] = error
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=vol.Schema({vol.Required(CONF_TOKEN): str}), errors=errors
        )
