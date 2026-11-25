# TLS cases

Whether a device can be revived depends almost entirely on how it treats TLS.

| Case | Recording | Revival | Result in the profile |
|---|---|---|---|
| **Plaintext** (HTTP, MQTT on 1883, CoAP, raw) | Passive or proxy; full content | Fully supported | `tls.mode: none`, `revivable` |
| **Accepts Modigliani's local CA**: no certificate verification, or an owner-configurable server or CA | Proxy mode terminates TLS with a local-CA certificate, forwards to the real vendor, and records plaintext | Server presents local-CA certificates for the profile's hostnames | `tls.mode: local_ca`, flows `accepted_local_ca` |
| **Strictly verifies the vendor's certificate** | The device rejects the local-CA certificate: recorded as `rejected_local_ca`. Its later connections to that host pass through untouched, keeping only sizes and timing | **Not revivable without firmware access** | `revivability.status: not_revivable_without_firmware_access`, `tls.mode: strict_verification`, hosts with outcomes `rejected_local_ca`/`passthrough` |
| **Encrypted and recorded passively** | Only SNI, sizes and timing | Unknown until tested | `partial`, outcome `untested`, with the reason "record again with `--mode proxy`" |

## What Modigliani never does

- It never retries a rejected handshake with tricks: no downgrade, no certificate games, no
  pinning bypass.
- It never modifies firmware or extracts keys from devices.
- It never cracks or decrypts traffic it is not a legitimate endpoint for.
- It never installs its CA into the PC's trust store. The CA is offered only to enrolled devices,
  and the server issues certificates only for hostnames named in loaded profiles.

A strictly verifying device keeps working with its vendor while you record: its traffic is
forwarded unchanged. The resulting profile documents the device (hostnames, timing, sizes) so the
community knows it needs firmware-level work, which is outside Modigliani's scope.

## How rejection is detected

In proxy mode, mitmproxy's `tls_failed_client` event fires when the device aborts the handshake
after receiving the local-CA certificate (for example with an `unknown ca` alert). The recorder
remembers the device and SNI pair. From then on its `next_layer` hook replaces the TLS layer with
a plain TCP layer for that pair, so bytes are forwarded unchanged and only their sizes and timing
are recorded.

The end-to-end suite includes **LockedHub**, a simulated device that pins the vendor CA. It must
produce `not_revivable_without_firmware_access` with metadata only, and it must keep reaching its
cloud during recording.
