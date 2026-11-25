# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-25

### Added

- Studio CLI: `enroll`, `record` (passive hotspot/gateway capture with Npcap or libpcap; proxy
  mode with mitmproxy, including wildcard SNI routes and router-mode DNS), `import`, `annotate`,
  `infer`, `review`, `test`, `export --share`, `install`, `keygen`, `verify`, `ca init|show` and
  `doctor`.
- Local CA with DPAPI-protected keys on Windows and owner-only key files elsewhere.
- Decoders for HTTP/1.x, WebSocket, MQTT 3.1.1 and 5, CoAP, and TLS ClientHello metadata; TCP
  reassembly for pcap import.
- Inference of path and topic templates, JSON schemas, token authentication flows, MQTT
  request/response pairs, binary framing, checksums and field layouts, state variables and
  commands from annotations, housekeeping (time sync and "no update" firmware checks), and
  Home Assistant entity mappings, all with evidence.
- Profile format v1 with a JSON Schema, semantic validation, scrubbing for sharing, ed25519
  signatures and placeholder filling on install.
- Modigliani Server (Go): DNS responder for enrolled devices, HTTP(S), WebSocket, embedded MQTT
  broker, CoAP and raw TCP/UDP handlers, certificate issuance from the local CA, SQLite state
  store, token-protected REST and WebSocket API, status page and Home Assistant MQTT discovery.
- Home Assistant custom integration with config flow, re-authentication, seven platforms, a
  `send_command` service and redacted diagnostics.
- Signed test-device profiles in `profiles/library`.
- Device and vendor-cloud simulators (SmartPlug, Thermostat, Sensor, LockedHub) and an
  end-to-end suite running on loopback.
- CI on Linux and Windows, CodeQL, Dependabot, and tagged releases with PyInstaller, multi-platform
  server binaries, a Docker image, SHA256SUMS and build provenance attestations.

[Unreleased]: https://github.com/ide-bloom/modigliani/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ide-bloom/modigliani/releases/tag/v0.1.0
