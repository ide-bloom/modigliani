# Scrubbing and sharing

A profile inferred from your capture contains your device's identifiers. Before you share it,
`modigliani export <profile> --share`:

1. **Scrubs** it (`studio/src/modigliani/profile/scrub.py`).
2. Prints the **full diff** (path, before, after, reason) and asks for confirmation. `--yes`
   accepts without prompting, which is meant for automation. Studio's *Share* tab shows the same
   diff.
3. Checks that no placeholder value survived in the written file, and refuses to export if one
   did.
4. **Signs** the file with your ed25519 key (`modigliani keygen` creates the key in your user
   configuration directory, outside any repository) and writes `<profile>.sig`.

## What is scrubbed

Detection uses three sources, and every occurrence of a detected value is replaced consistently:

1. **Known placeholders**: values inference already knows are per-device (path parameters such
   as serials, MQTT client-ID and topic identities, login-body serials and device IDs).
2. **Sensitive key names** inside message data (bodies, payloads, templates, replies, schemas):
   `serial`, `sn`, `mac`, `ssid`, `wifi`, `password`, `secret`, `token`, `api_key`, `key`,
   `email`, `account`, `user`, `owner`, `device_id`, `uuid`, `imei`, `lat`/`lon`, `home`,
   `room`, `nickname`, and similar. Structural keys of the profile itself (entity `key`, handler
   `id`, ...) are not affected.
3. **Value shapes** anywhere: MAC addresses (in every separator style), e-mail addresses, IPv4
   addresses, UUIDs, token-shaped strings, and runs of 8 or more digits.

Replacements:

- Values in templates and literals become `{{ph.<kind>_<n>}}` placeholders, for example
  `{{ph.account_1}}`.
- In regular expressions (`fingerprints[].pattern`, placeholder sources) they become `.+`.
- Placeholder `value`s are removed. Their `source` (how to find the value in a capture) is kept.
- Capture names become `capture-1`, `capture-2`, ..., capture hashes become `scrubbed`, and host
  timestamps become relative times.
- `provenance.scrubbed` is set to `true`, which makes the server verify the signature.

The test `tests/unit/test_profile.py::test_scrub_removes_every_identifier` plants identifiers of
every kind and checks that none survives in the YAML or JSON output. The end-to-end suite checks
the shared profiles of all three test devices.

**Limitation:** constant bytes inside binary frames (`const_*` fields) are not scrubbed
automatically, because they cannot be told apart from protocol magic. Review them in the diff
before sharing.

## Installing a shared profile

```powershell
modigliani install profiles/library/test-smartplug.yaml mycapture
```

This verifies the signature, fills each placeholder from your own capture using its `source`
(path parameter, body field, header, MQTT client ID, username or topic, CoAP path), generates
fresh values for token, key and secret placeholders, and writes `profiles/local/<id>.yaml`. Use
`--set NAME=VALUE` for anything it cannot find.

## Licensing

Shared profiles are licensed CC0-1.0 or CC-BY-4.0 (`--license`; `--author` for attribution),
as recorded in `provenance.license`. The code is Apache-2.0.
