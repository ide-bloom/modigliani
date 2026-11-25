# Profile library

Scrubbed, signed community profiles. Each `<id>.yaml` has a detached `<id>.yaml.sig` (ed25519
over the exact file bytes). Install one with your own capture:

```powershell
modigliani install profiles/library/<id>.yaml <your-capture>
```

| Profile | Device | Status | License |
|---|---|---|---|
| `test-smartplug` | SmartPlug simulator (HTTPS, token login, command polling) | revivable | CC0-1.0 |
| `test-thermostat` | Thermostat simulator (MQTT over TLS, time sync) | revivable | CC0-1.0 |
| `test-sensor` | Sensor simulator (CoAP, binary frames with CRC-8) | revivable | CC0-1.0 |
| `test-lockedhub` | LockedHub simulator (strict certificate verification) | not revivable without firmware access | CC0-1.0 |

The test-device profiles were inferred from a recording of the simulators in `tests/devices`,
made through proxy mode with localhost port mapping. Their host reports therefore show loopback
ports rather than vendor ports.

They are signed with the maintainer key below, which `server/config.example.yaml` lists in
`trusted_keys`. Add it to your server's `trusted_keys` to have these profiles reported as verified:

| Key id | Public key (base64 ed25519) |
|---|---|
| `8d0fe4e75b91da4b` | `iRaa1UoXv3eL5mnl0ggXX6arGLuIf6Q3vUkjXeNTs1w=` |

Contributions are welcome: see [CONTRIBUTING.md](../../CONTRIBUTING.md#contributing-a-profile).
Each profile is licensed CC0-1.0 or CC-BY-4.0, as recorded in its `provenance.license`.
