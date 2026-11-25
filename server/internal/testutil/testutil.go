// Package testutil provides a profile and engine covering every handler type for tests.
package testutil

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/ide-bloom/modigliani/server/internal/engine"
	"github.com/ide-bloom/modigliani/server/internal/profile"
	"github.com/ide-bloom/modigliani/server/internal/store"
)

// ProfileYAML exercises HTTP (login, polling, extract), WebSocket, MQTT (telemetry,
// request/response, commands), CoAP with binary frames, and raw TCP.
const ProfileYAML = `
schema_version: 1
id: lab
name: Lab Device
device: {vendor: Test, model: T1}
revivability: {status: revivable}
dns: {names: [api.lab.example, mqtt.lab.example, "{{ph.serial}}.lab.example"]}
tls: {mode: local_ca, hostnames: [api.lab.example, mqtt.lab.example]}
placeholders:
  serial: {kind: serial, value: SN-1}
auth:
  token: {format: hex, length: 32, lifetime_s: 3600, location: bearer, name: Authorization, issued_by: login}
  mqtt: {client_id_pattern: "lab-{device_id}", username_pattern: "{device_id}", password: accept_any}
state:
  - {name: power, type: bool, writable: true}
  - {name: watts, type: float, unit: W}
  - {name: setpoint, type: float, unit: "°C", min: 5, max: 35, step: 0.5, writable: true}
  - {name: temp, type: float, unit: "°C"}
  - {name: mode, type: enum, options: [heat, cool], writable: true}
  - {name: led, type: bool, writable: true}
  - {name: level, type: int}
commands:
  - {name: set_power, variable: power, transport: http_poll, handler: poll, template: {seq: "{{gen.seq}}", on: "{{cmd.value}}"}, value_map: {"true": "ON", "false": "OFF"}}
  - {name: set_setpoint, variable: setpoint, transport: mqtt, handler: cmd, template: {setpoint: "{{cmd.value}}"}}
  - {name: set_mode, variable: mode, transport: mqtt, handler: cmd, template: {mode: "{{cmd.value}}"}}
  - {name: set_led, variable: led, transport: coap_response, handler: telemetry, value_map: {"true": 1, "false": 0}}
frames:
  - id: up
    length: 7
    fields:
      - {name: magic, offset: 0, type: u8, const: 165}
      - {name: temp, offset: 2, type: i16be, scale: 0.1}
      - {name: led, offset: 4, type: u8}
      - {name: level, offset: 5, type: u8}
    length_field: {offset: 1, type: u8, adjust: 3}
    checksum: {algorithm: crc8, offset: -1, start: 1, end: -1}
  - id: down
    length: 4
    fields:
      - {name: magic, offset: 0, type: u8, const: 165}
      - {name: led, offset: 2, type: u8}
    length_field: {offset: 1, type: u8, adjust: 3}
    checksum: {algorithm: crc8, offset: -1, start: 1, end: -1}
handlers:
  http:
    - id: login
      host: api.lab.example
      method: POST
      path: /v1/login
      identity: req.body.serial
      auth: issue_token
      response: {status: 200, body_type: json, body: {token: "{{token.value}}", ttl: "{{token.expires_in}}"}}
    - id: poll
      method: GET
      path: /v1/dev/{serial}/poll
      identity: req.path.serial
      auth: token
      delivers_commands: {mode: list, path: queue}
      response: {status: 200, body_type: json, body: {queue: []}}
    - id: report
      method: POST
      path: /v1/dev/{serial}/report
      identity: req.path.serial
      auth: token
      extract:
        - {source: req.body.on, variable: power, value_map: {'"ON"': true, '"OFF"': false}}
        - {source: req.body.w, variable: watts}
      response: {status: 200, body_type: json, body: {ok: true, echo: "{{req.path.serial}}", at: "{{now.unix}}"}}
    - id: time
      method: GET
      path: /v1/time
      housekeeping: time_sync
      response: {status: 200, body_type: json, body: {epoch: "{{now.unix}}"}}
  websocket:
    - id: ws
      path: /ws/{serial}
      identity: req.path.serial
      messages:
        - id: ping
          match: {type: ping}
          reply: {type: pong, id: "{{req.payload.id}}"}
        - id: state
          match: {type: state}
          extract: [{source: req.payload.watts, variable: watts}]
  mqtt:
    hosts: [mqtt.lab.example]
    identity_var: device_id
    topics:
      - {id: telemetry, topic: "lab/{device_id}/tele", direction: device_to_cloud, extract: [{source: req.payload.t, variable: temp}, {source: req.payload.sp, variable: setpoint}]}
      - {id: time_req, topic: "lab/{device_id}/time/get", direction: device_to_cloud}
      - {id: time_resp, topic: "lab/{device_id}/time", direction: cloud_to_device, reply_to: time_req, payload: {now: "{{now.unix}}", ask: "{{req.payload.n}}"}}
      - {id: cmd, topic: "lab/{device_id}/cmd", direction: cloud_to_device, qos: 1}
  coap:
    - id: telemetry
      method: POST
      path: /d/{id}/t
      identity: req.path.id
      request_frame: up
      extract: [{source: req.fields.temp, variable: temp}, {source: req.fields.led, variable: led, value_map: {"1": true, "0": false}}]
      response: {code: "2.04", payload_type: frame, frame: {frame: down, values: {led: "{{desired.led}}"}}}
  raw:
    - id: raw
      transport: tcp
      port: 9000
      framing: {kind: length_prefixed, length_field: {offset: 1, type: u8, adjust: 3}}
      rules:
        - id: up
          frame: up
          match: {magic: 165}
          extract: [{source: req.fields.level, variable: level}]
          reply: {frame: down, values: {led: "{{desired.led}}"}}
home_assistant:
  entities:
    - {platform: switch, key: power, name: Power, variable: power}
    - {platform: sensor, key: watts, name: Watts, variable: watts, unit: W, device_class: power, state_class: measurement}
    - {platform: climate, key: climate, name: Lab, current_temperature: temp, target_temperature: setpoint, hvac_mode: mode, hvac_mode_map: {heat: heat, cool: cool}, min: 5, max: 35, step: 0.5, unit: "°C"}
    - {platform: light, key: led, name: LED, variable: led}
    - {platform: number, key: level, name: Level, variable: level, min: 0, max: 10, step: 1}
    - {platform: select, key: mode, name: Mode, variable: mode, options: [heat, cool]}
    - {platform: binary_sensor, key: led_state, name: LED state, variable: led}
provenance: {generated_by: test, created: "2026-01-01T00:00:00Z"}
`

// Profile parses ProfileYAML.
func Profile(t testing.TB) *engine.Loaded {
	t.Helper()
	p, err := profile.Parse([]byte(ProfileYAML), "lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return &engine.Loaded{Profile: p, Path: "lab.yaml"}
}

// Engine builds an engine over the lab profile with an in-memory store.
func Engine(t testing.TB) *engine.Engine {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return engine.New(Logger(), st, []*engine.Loaded{Profile(t)}, engine.Options{DeviceTimeout: time.Minute})
}

// Logger discards output.
func Logger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// CRC8 matches the profile checksum (poly 0x07).
func CRC8(b []byte) byte {
	var crc byte
	for _, c := range b {
		crc ^= c
		for range 8 {
			if crc&0x80 != 0 {
				crc = crc<<1 ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// UpFrame builds an "up" frame: A5 len temp(i16be x10) led level crc.
func UpFrame(temp float64, led, level byte) []byte {
	t := int16(temp * 10)
	b := []byte{0xA5, 4, byte(uint16(t) >> 8), byte(t), led, level, 0}
	b[6] = CRC8(b[1:6])
	return b
}
