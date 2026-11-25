"""Constants for the Modigliani integration."""

from __future__ import annotations

from datetime import timedelta
from typing import Final

DOMAIN: Final = "modigliani"
CONF_TOKEN: Final = "token"
DEFAULT_URL: Final = "http://127.0.0.1:8080"
SCAN_INTERVAL: Final = timedelta(seconds=10)
SERVICE_SEND_COMMAND: Final = "send_command"
ATTR_VARIABLE: Final = "variable"
ATTR_VALUE: Final = "value"
