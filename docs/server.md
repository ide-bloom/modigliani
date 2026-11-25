# Modigliani Server

```text
modigliani-server --profiles <file-or-dir> [--profiles ...] --config <file> [--log-format text|json] [--version]
```

The server loads every `*.yaml`, `*.yml` and `*.json` profile under `--profiles`, recursively.
It skips profiles with invalid signatures and profiles marked
`not_revivable_without_firmware_access`, and logs why. A commented example configuration is in
[`server/config.example.yaml`](../server/config.example.yaml); unknown keys are errors.

## Configuration

| Key | Default | Meaning |
|---|---|---|
| `data_dir` | `modigliani-data` | SQLite database and generated API token. |
| `ca_dir` | `ca` | The CA created by `modigliani ca init`. On Windows the key is DPAPI-protected, so run the server as the same user. |
| `profiles` | | Extra profile paths (added to `--profiles`). |
| `api.listen` / `api.token` / `api.token_file` | `127.0.0.1:8080` / generated into `<data_dir>/api-token` | Local API and status page. |
| `http.listen` / `http.tls_listen` | `:80` / `:443` if profiles need HTTP | Device-facing HTTP and HTTPS. |
| `mqtt.listen` / `mqtt.tls_listen` | `:1883` / `:8883` if profiles need MQTT | Embedded broker. |
| `coap.listen` | `:5683` if profiles need CoAP | CoAP over UDP. |
| `raw.listen` | each handler's own port | Map `"tcp/9000": ":19000"` to move a raw handler. |
| `enrolled` | `[]` | `{name, ip, mac}`. When set, only these clients are served on device-facing listeners. DNS always requires enrollment. |
| `dns.listen` / `dns.answer_ip` / `dns.upstream` | off / none / `1.1.1.1:53` | Answer enrolled devices' queries for profile hostnames with `answer_ip`; forward other names upstream. |
| `home_assistant.*` | off | `broker` (`tcp://`, `ssl://`, `ws://`), `username`, `password`, `client_id`, `discovery_prefix` (`homeassistant`), `base_topic` (`modigliani`). |
| `trusted_keys` | `[]` | Base64 ed25519 public keys trusted for library profiles. |
| `time_offset_s` | `0` | Offset added to the time presented to devices. |
| `device_timeout_s` | `120` | A device not heard from within this time is offline. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |

A listener section that is absent gets defaults when a profile needs that protocol. A section
that is present is used exactly as written. TLS listeners need the CA, and certificates are
issued only for hostnames named in loaded profiles.

Binding ports below 1024 on Linux needs root or `CAP_NET_BIND_SERVICE`. Alternatively, keep the
defaults off and use a router or iptables redirect.

## Behavior

- **Identity.** Each handler's `identity` expression (for example `req.path.serial`) gives the
  device key. Without one, the key is the token's device or, if the handler extracts state, the
  client IP. Anonymous housekeeping requests do not create devices.
- **Auth emulation.** `issue_token` handlers create tokens in the profile's format, lifetime and
  prefix (JWT-shaped tokens carry `iat`/`exp`). `token` handlers answer `401` to unknown or
  expired tokens. MQTT clients must match the profile's client ID and username patterns; clients
  that match no profile are refused.
- **State store.** SQLite holds devices (with learned path/topic variables), reported and desired
  values, the command queue, tokens, per-device counters and unhandled requests (capped at
  5,000). A desired value is cleared once the device reports it.
- **Unhandled requests** get the profile's default response (HTTP), `4.04` (CoAP), or no answer
  (raw). They are stored and shown on the status page and at `/api/unhandled`, so you can record
  again and improve the profile.

## Local API

Every endpoint except `/api/health` and `/` needs `Authorization: Bearer <token>`. WebSocket
clients may pass `?token=` instead.

| Method and path | Description |
|---|---|
| `GET /api/health` | `{"status":"ok","version":...,"profiles":N}` |
| `GET /api/devices` | Devices with `id` (`profile/key`), `online`, `last_seen`, `state`, `desired`, `variables`, `entities`, `commands`. |
| `GET /api/devices/{profile}/{key}` | One device. |
| `POST /api/devices/{profile}/{key}/commands` | `{"variable": "power", "value": true}` or `{"command": "set_power", "value": true}`. Answers `202` with `status` `queued`, `sent` or `pending_next_contact`; `400` for invalid values (type, range, enum); `404` for unknown devices. |
| `GET /api/profiles` | Loaded profiles with signature status and hostnames. |
| `GET /api/unhandled?limit=N` | Recent unhandled requests. |
| `GET /api/logs` | Recent log records. |
| `GET /api/events` | WebSocket stream of `device`, `state` and `command` events. |
| `GET /` | Status page: devices, last seen, unhandled requests, logs. |

## Docker

```bash
docker build -t modigliani-server server/
docker run --network host \
  -v "$PWD/profiles/local:/profiles:ro" -v "$PWD/config:/config:ro" \
  -v "$PWD/ca:/ca:ro" -v modigliani-data:/data modigliani-server
```

Set `data_dir: /data` and `ca_dir: /ca` in `/config/config.yaml`. Use a CA created on Linux:
DPAPI keys can only be decrypted on Windows.
