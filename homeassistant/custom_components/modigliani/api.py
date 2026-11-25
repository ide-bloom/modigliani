"""Client for the Modigliani Server local API."""

from __future__ import annotations

from typing import Any

import aiohttp


class ModiglianiError(Exception):
    """The server could not be reached or answered unexpectedly."""


class ModiglianiAuthError(ModiglianiError):
    """The API token was rejected."""


class ModiglianiApi:
    """Thin async wrapper around the REST API (see docs/server.md)."""

    def __init__(self, session: aiohttp.ClientSession, url: str, token: str) -> None:
        self._session = session
        self._url = url.rstrip("/")
        self._token = token

    async def _request(self, method: str, path: str, json: Any = None) -> Any:
        try:
            async with self._session.request(
                method,
                f"{self._url}{path}",
                json=json,
                headers={"Authorization": f"Bearer {self._token}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 401:
                    raise ModiglianiAuthError("invalid API token")
                data = await resp.json(content_type=None)
                if resp.status >= 400:
                    message = data.get("error") if isinstance(data, dict) else resp.reason
                    raise ModiglianiError(f"HTTP {resp.status}: {message}")
                return data
        except (aiohttp.ClientError, TimeoutError) as err:
            raise ModiglianiError(str(err)) from err

    async def devices(self) -> list[dict[str, Any]]:
        data = await self._request("GET", "/api/devices")
        return data if isinstance(data, list) else []

    async def send_command(self, profile: str, key: str, variable: str, value: Any) -> dict[str, Any]:
        data = await self._request(
            "POST", f"/api/devices/{profile}/{key}/commands", json={"variable": variable, "value": value}
        )
        return data if isinstance(data, dict) else {}
