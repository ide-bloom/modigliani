"""LockedHub: HTTPS client that strictly verifies the vendor's certificate (pinned vendor CA).

Through Modigliani's proxy its handshakes fail, as they should: it must be reported as
"not revivable without firmware access".
"""

from __future__ import annotations

import http.client
import json
import ssl

from tests.devices.base import Device
from tests.support.net import SniHTTPSConnection, Target

HUB_ID = "HUB-55AA01"


class LockedHub(Device):
    name = "lockedhub"

    def __init__(self, target: Target, vendor_ca: str, interval: float = 1.0) -> None:
        super().__init__()
        self.target = target
        self.vendor_ca = vendor_ca
        self.interval = interval
        self.tls_failures = 0

    def run(self) -> None:
        ctx = ssl.create_default_context(cafile=self.vendor_ca)
        n = 0
        while self.sleep(self.interval):
            n += 1
            conn = SniHTTPSConnection(self.target, ctx)
            try:
                body = json.dumps({"hub": HUB_ID, "seq": n, "zones": 4}).encode()
                conn.request(
                    "POST",
                    "/hub/v2/report",
                    body=body,
                    headers={"Host": self.target.hostname, "Content-Type": "application/json"},
                )
                if conn.getresponse().status == 200:
                    self.health.authenticated = True
                    self.health.ok()
            except ssl.SSLError as exc:
                self.tls_failures += 1
                self.health.error(f"tls: {exc}")
            except (OSError, http.client.HTTPException) as exc:
                self.health.error(str(exc))
            finally:
                conn.close()
