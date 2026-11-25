# Home Assistant

There are two ways to use revived devices in Home Assistant. Pick one per device; using both at
once creates duplicate entities.

## MQTT discovery (no custom code)

Add to the server configuration:

```yaml
home_assistant:
  broker: tcp://homeassistant.local:1883
  username: modigliani
  password: your-password
```

The server connects to your broker. It publishes `modigliani/status` (`online`, retained, with
an `offline` last will) and, for every device, retained discovery configs under
`homeassistant/<platform>/<profile>_<key>/<entity>/config`. Each config has a `unique_id`,
device information and two availability topics (server and device).

| Topic | Content |
|---|---|
| `modigliani/<slug>/state` | JSON with all reported variables, plus `__hvac_mode`/`__hvac_action` for climate entities |
| `modigliani/<slug>/availability` | `online` / `offline` |
| `modigliani/<slug>/set/<variable>` | Commands from Home Assistant (`ON`/`OFF`, numbers, option names) |
| `modigliani/<slug>/set_hvac/<variable>` | Climate HVAC modes, mapped back to device values |

Supported platforms: `climate` (current and target temperature, HVAC mode and action), `switch`,
`light` (on/off), `sensor` (unit, device class, state class), `binary_sensor`, `select` and
`number`. The entity mapping comes from the profile's `home_assistant.entities`. You can edit it
in `modigliani review`.

## Custom integration (no MQTT)

Install with HACS: add `https://github.com/ide-bloom/modigliani` as a custom repository of type
*Integration*. Releases include `modigliani-homeassistant.zip`. Alternatively, copy
`homeassistant/custom_components/modigliani` to `<config>/custom_components/`. Requires Home
Assistant 2026.10 or newer.

Then go to *Settings > Devices & services > Add integration > Modigliani* and enter:

- **Server URL**: the local API, for example `http://192.168.1.10:8080`. Make the API reachable
  by setting `api.listen` to an address Home Assistant can reach.
- **API token**: `api.token` from the configuration, or the contents of `<data_dir>/api-token`.

The integration polls `/api/devices` every 10 seconds. It creates the same entity types as MQTT
discovery, with devices identified as `profile/key`, and adds entities for devices that appear
later. Devices the server reports offline become unavailable. If the token is rejected, Home
Assistant asks you to re-authenticate.

**Service** `modigliani.send_command`, fields `device_id`, `variable`, `value`:

```yaml
action: modigliani.send_command
data:
  device_id: 7c1f...            # the Home Assistant device
  variable: setpoint
  value: 21.5
```

**Diagnostics** (*Download diagnostics*) include device state but redact the token, device keys,
device IDs and remote addresses.

## Tests

`homeassistant/tests` runs with `pytest-homeassistant-custom-component` (`cd homeassistant &&
pytest`). Home Assistant does not run on Windows, so CI runs these tests on Linux.
