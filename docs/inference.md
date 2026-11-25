# Inference

`modigliani infer` turns captures and annotations into a profile. Each rule below is implemented
in `studio/src/modigliani/infer/` and covered by tests in `tests/unit/`. Every inferred element
keeps evidence: capture, flow and message index.

## Sessions and protocol detection (`sessions.py`, `decoders.py`)

- TCP flows are byte streams in each direction. The first bytes decide the protocol: an HTTP
  method means HTTP/1.x; a CONNECT packet whose protocol name is `MQTT` or `MQIsdp` means MQTT
  (3.1.1 or 5, with v5 property blocks skipped); a TLS record from a passive capture means
  metadata only; anything else is raw.
- UDP flows are CoAP when every datagram parses as CoAP version 1. Otherwise each datagram is a
  raw message.
- HTTP decoding handles keep-alive, `Content-Length`, chunked bodies, gzip/deflate, HEAD/204/304,
  and the WebSocket upgrade. Bytes after a `101` response are decoded as WebSocket frames,
  including masked and fragmented messages.
- Flows recorded as `rejected_local_ca`, `passthrough` or `untested` become TLS observations
  (host, port, sizes, timing) and are never decoded.

## Revivability (`engine.py`)

- No decodable traffic, and some host rejected the local CA: `not_revivable_without_firmware_access`.
  The profile then contains only DNS names, fingerprints and the host report.
- Some decodable traffic, plus rejected or untested hosts: `partial`, with a reason per host.
- Otherwise: `revivable`.

## HTTP (`templates.py`, `engine.py`)

- **Path templates.** A segment becomes a parameter when it looks like an identifier: a UUID, a
  MAC address, digits, hex of 8 characters or more, or a mix of letters and digits of 5
  characters or more. A segment also becomes a parameter when it equals a known identifier.
  Version segments (`v1`) and plain words never do, so `/status` and `/commands` stay separate.
- **Parameter names** come from known values first: a segment equal to the login body's `serial`
  is named `serial`. Otherwise the preceding segment is used (`devices/{device_id}`).
- **Known identifiers** are request-body fields named like serials or device IDs (`serial`, `sn`,
  `device_id`, `mac`, ...), path parameters, and MQTT topic segments that appear in the client ID
  or username. They become profile placeholders.
- **Handlers** are grouped by host, method and path template. Each records the request JSON
  schema (genson), the most common status, headers, body type, and the polling interval (the
  median gap between requests).
- **Response templates** are built from the most common response shape. Values are replaced in
  this order of precedence: the issued token becomes `{{token.value}}`; a token lifetime field
  becomes `{{token.expires_in}}`; a value equal to a path parameter, query parameter or request
  body field becomes a request reference; a current time (within two days, seconds or
  milliseconds since the epoch, or ISO 8601) becomes `{{now.unix}}`, `{{now.unix_ms}}` or
  `{{now.iso}}`; a value that differs in every response becomes a generator (`{{gen.seq}}` for
  increasing integers, `{{gen.uuid}}`, `{{gen.hex.N}}`, `{{gen.alnum.N}}`). Everything else
  stays literal.

## Authentication flows (`auth.py`)

- **Login rule.** A response value shaped like a token (UUID, JWT, hex of 16 characters or more,
  or long alphanumeric/base64url), or found under a key named `token`, `session` or `jwt`, that
  the device later presents in a header (`Authorization: Bearer`, or any custom header), a query
  parameter or a body field. That response's endpoint becomes the token issuer
  (`auth: issue_token`), and endpoints that present the token require it (`auth: token`).
- **Format and lifetime.** The format and length come from the token. The lifetime comes from a
  sibling field (`expires_in`, `ttl`, `expires`, ...), from a JWT's `exp - iat`, or from the
  shortest interval between logins.
- The server issues new tokens in the same format and accepts the device's own credentials. It
  never needs the vendor's secrets. For MQTT, the client ID and username patterns are learned,
  and passwords are accepted as presented.

## MQTT

- Topics are templated like paths; the identity segment is named `device_id`.
- Each topic records its direction (who published), the highest QoS seen, retain flags, payload
  type and JSON schema. The session records protocol levels and keepalive.
- **Request/response rule.** A cloud-to-device topic is a reply to a device-to-cloud topic when
  every cloud publish follows a device publish on that topic within 1.5 s, and at least 80% of
  the device publishes get an answer. The reply payload becomes a template; time values become
  `{{now.*}}`.

## CoAP and raw protocols (`frames.py`)

- CoAP requests are grouped by method and path template, and responses are paired by token. JSON
  payloads are handled like HTTP bodies. Binary payloads are frames.
- **Checksum rule.** Search sum8, xor8, crc8 (poly 0x07), sum16, CRC-16/CCITT-FALSE,
  CRC-16/MODBUS and CRC-32, in both endians, at the end of the frame, covering bytes from offset
  0 to 3 up to the checksum. A combination is accepted only if it holds for every binary payload
  of the device and for at least two distinct frames.
- **Length field rule.** A 1- or 2-byte field at offsets 0 to 3 whose value, plus a conventional
  adjustment, equals the frame length. The conventions are: counts the bytes after the field
  excluding the checksum, including it, the whole frame, or everything except the checksum. The
  field is inferred across all frame types of the device, because one frame type alone is
  ambiguous.
- **Field rule.** Annotation values are matched against every offset, width (8/16/32 bits),
  endianness, signedness and scale (1, 0.1, 0.01, 0.5) in a time window: after the tap for
  actions, just before it for readings. Boolean actions only match bytes that change. A matching
  byte preceded by a byte that is always zero is widened to a 16-bit big-endian field. Remaining
  constant bytes become `const_<offset>` fields. Remaining varying bytes become `field_<offset>`
  fields (a slowly changing byte followed by a fast one becomes a 16-bit field).
- **Raw framing rule** for TCP streams, tried in order:
  1. delimiter: `\r\n`, `\n`, NUL, 0x7E or 0x03, when the stream ends with it and splits into at
     least 3 frames;
  2. length-prefixed: a field that walks every stream exactly into at least 2 frames, with no
     zero lengths;
  3. fixed-size records whose first byte is constant;
  4. otherwise each segment is a message.
- Raw message types are frame layouts grouped by direction and length. Device frames get
  replies when a cloud frame follows within 2 s.

## State model (`state.py`)

Fields from every message (JSON paths, form fields, query parameters, decoded frame fields)
become time series per channel. Counters (increasing integers that never repeat, or fields
named like `uptime`, `seq`, `ts`) and clocks are excluded first.

- **Command rule.** After an action annotation with value V, a cloud-to-device field that carries
  V within [t-2 s, t+15 s] is the command encoding.
- **Report rule.** A device-to-cloud field whose value becomes V within [t, t+30 s] reports the
  variable. A field that already held V before t scores lower.
- **Reading rule.** A reading annotation marks the device-to-cloud field that carries the value
  within ±10 s, possibly scaled.
- **Encodings.** Booleans may be `true`/`false`, `1`/`0` (only in fields that only hold two
  values), or strings such as `on`/`off`. Numbers may be scaled by 10, 100 or 2. These become
  value maps and scales in extracts and commands.
- **Name rule.** Without annotations, a cloud-to-device field with the same name as a reported
  field is a command for it.
- **Variation rule.** Other varying device-to-cloud fields become read-only sensors.
- **Types and ranges.** Types are bool, int, float, enum (8 values or fewer) or string. Units come
  from annotations or names (temperature °C, humidity and battery %, watts W, kWh, V). Writable
  temperatures get the range 5 to 35 °C in steps of 0.5; other numbers get the range observed.

**Commands** are attached to the channel where the command field appeared: a polled HTTP
response (`http_poll`, with the item template and the list path), an MQTT topic (`mqtt`, with the
payload template), a CoAP or raw reply frame (`coap_response`/`raw`, with the frame field set to
`{{desired.var}}`), or a WebSocket message.

## Housekeeping

- Paths or topics containing `time`, `clock`, `ntp`, `date`, `epoch` or `sync` are marked
  `time_sync`, and their time values are rendered from the server clock. Both the server and the
  profile can set an offset.
- Paths or topics containing `firmware`, `fw`, `ota`, `update` or `upgrade` are marked
  `firmware_check`. Boolean "update available" fields are forced to false and download URLs to
  empty strings, so devices are always told "no update".

## Home Assistant mapping

- A writable temperature plus a temperature reading or a writable mode becomes a `climate`
  entity. HA modes are mapped by name (heat, cool, auto, dry, fan_only, off).
- Writable booleans become `switch`, or `light` when named like lights. Writable numbers become
  `number`, writable enums become `select`.
- Read-only numbers become `sensor` (device class from the unit), read-only booleans
  `binary_sensor`, and read-only enums `sensor` with options.
