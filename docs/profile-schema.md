# Profile schema (version 1)

A profile is a YAML or JSON document. The authoritative JSON Schema is
[`profile.schema.json`](profile.schema.json). It is generated from the pydantic model in
`studio/src/modigliani/profile/model.py` by `uv run python scripts/gen_schema.py`, and a unit
test fails when the two drift apart. The Go server reads the same fields
(`server/internal/profile/profile.go`).

Validate a profile with `modigliani verify <profile>`. It runs the JSON Schema, then semantic
checks: references between commands, handlers, frames and Home Assistant entities, and template
expressions.

## Top level

| Key | Meaning |
|---|---|
| `schema_version` | Always `1`. |
| `id`, `name` | Slug (`[a-z0-9._-]`) and display name. |
| `device` | `vendor`, `model`, `description`, `fingerprints` (regexes over SNI, DNS names, HTTP User-Agent, MQTT client ID, CoAP path or port). |
| `revivability` | `status` (`revivable`, `partial`, `not_revivable_without_firmware_access`), `reasons`, and per-host metadata (`hosts`: TLS outcome, flows, bytes, timing). |
| `dns` | `names` the server answers for enrolled devices; `ttl`. |
| `tls` | `mode` (`none`, `local_ca`, `strict_verification`, `mixed`) and `hostnames` that get local-CA certificates. |
| `placeholders` | Per-device values (`kind`, `description`, `value`, `source`). Shared profiles have `value: null`; `modigliani install` fills them using `source`. |
| `auth` | `token` (`format`, `length`, `prefix`, `lifetime_s`, `location`: bearer/header/query/body, `name`, `issued_by`) and `mqtt` (`client_id_pattern`, `username_pattern`, `password: accept_any`). |
| `state` | Variables: `name`, `type` (bool/int/float/enum/string), `unit`, `min`, `max`, `step`, `options`, `writable`. |
| `commands` | `name`, `variable`, `transport` (`http_poll`, `mqtt`, `coap_response`, `websocket`, `raw`), `handler`, `template`, `value_map` (state value as JSON text to device value), `scale` (device value = state value / scale). |
| `frames` | Binary layouts: `length`, `fields` (`name`, `offset`, `type` u8/i8/u16be/u16le/i16be/i16le/u32be/u32le/i32be/i32le, `scale`, `const`), `length_field` (`offset`, `type`, `adjust`: frame length = value + adjust), `checksum` (`algorithm`, `offset`, `start`, `end`, `endian`). |
| `handlers` | See below. |
| `housekeeping` | `time_source` (`system` or `offset`), `time_offset_s`, `firmware: no_update`. |
| `defaults` | `http` response for unhandled requests, `coap_code`. |
| `home_assistant.entities` | `platform` (climate/switch/light/sensor/binary_sensor/select/number), `key`, `name`, `variable`, `unit`, `device_class`, `state_class`, `min`/`max`/`step`, `options`; for climate: `current_temperature`, `target_temperature`, `hvac_mode`, `hvac_mode_map` (device value to HA mode), `hvac_action`. |
| `provenance` | `generated_by`, `created`, `captures` (name, sha256, mode), `author`, `license` (CC0-1.0 / CC-BY-4.0), `scrubbed`, `notes`. |

Most elements carry `evidence`: a list of `{capture, flow, message}`.

## Handlers

- **`http`**: `id`, `host`, `method`, `path` (template with `{name}` segments), `identity`
  (expression giving the device key), `auth` (`none`, `issue_token`, `token`), `extract`,
  `request_schema`, `response` (`status`, `headers`, `body_type` json/form/text/empty, `body`
  template), `delivers_commands` (`mode` list/replace, `path`), `housekeeping`,
  `polling_interval_s`.
- **`websocket`**: `path`, `identity`, `messages` (`match` on fields, `extract`, `reply` template).
- **`mqtt`**: `hosts`, `ports`, `tls`, `protocol_levels`, `keepalive_s`, `identity_var`, and
  `topics` (`id`, `topic` template, `direction`, `qos`, `retain`, `payload_type`,
  `payload_schema`, `extract`, `reply_to`, `payload` template, `housekeeping`).
- **`coap`**: `method`, `path`, `identity`, `request_frame`, `extract`, `response` (`code` such
  as `2.04`, `content_format`, `payload_type` empty/json/text/frame, `payload`, `frame` with
  `values`).
- **`raw`**: `transport`, `port`, `framing` (`datagram`, `delimiter` with hex `delimiter`,
  `length_prefixed` with `length_field`, `fixed` with `record_size`), `identity`, and `rules`
  (`frame`, `match` on constant fields, `extract`, `reply`).

An **extract** copies a value into reported state: `source` (an expression such as
`req.body.power`, `req.payload.temp` or `req.fields.temperature`), `variable`, `value_map`
(device value as JSON text to state value) and `scale` (state value = device value × scale).

## Templates

A string containing `{{ expr }}` is a template. A string that is exactly one expression keeps
the value's JSON type; otherwise values are interpolated as text. Unknown values render as
`null`.

| Expression | Value |
|---|---|
| `req.path.X`, `req.query.X`, `req.header.x` (lowercase), `req.body.a.b.0` | HTTP request parts |
| `req.topic.X`, `req.payload.a.b` | MQTT topic variables and payload |
| `req.fields.X` | Decoded binary frame fields (scaled) |
| `device.key`, `device.vars.X` | The device and the variables learned from its paths/topics |
| `state.X`, `desired.X` | Reported value; desired value (or reported if none), both in device encoding |
| `cmd.value`, `cmd.name`, `cmd.seq`, `cmd.id` | The command being rendered (`cmd.value` is in device encoding) |
| `token.value`, `token.expires_in`, `token.expires_at` | The token issued by this response |
| `ph.X` | Placeholder values |
| `now.unix`, `now.unix_ms`, `now.iso` | Server time (with configured offsets) |
| `gen.uuid`, `gen.seq`, `gen.hex.N`, `gen.alnum.N` | Generated values (`gen.seq` is a per-device counter) |

## Signatures

A shared profile `x.yaml` is accompanied by `x.yaml.sig`:

```json
{"algorithm": "ed25519", "key_id": "<sha256(pub)[:16]>", "public_key": "<base64>", "signature": "<base64>"}
```

The signature covers the exact bytes of the profile file. The server verifies profiles with
`provenance.scrubbed: true` (library profiles). It refuses invalid signatures, warns on unsigned
or untrusted ones, and trusts the keys listed in `trusted_keys`.
