# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/ide-bloom/modigliani/security/advisories/new).
Do not open a public issue. Include the affected component (Studio, Modigliani Server or the
Home Assistant integration), the version, and steps to reproduce.

We aim to acknowledge reports within 7 days and to publish a fix or mitigation within 90 days,
coordinating disclosure with you.

## Supported versions

Only the latest release receives security fixes.

## Scope and design commitments

These are part of the security model. A way to break any of them is a vulnerability:

- Only enrolled devices are resolved, proxied, recorded or served (when enrollment is configured).
- The local CA key is encrypted at rest (DPAPI on Windows, owner-only permissions elsewhere). It
  is never installed into the host trust store, and certificates are issued only for hostnames
  named in loaded profiles.
- The local API requires a token for everything except the health check and the static status
  page.
- Shared profiles contain no identifiers after scrubbing, and invalid signatures are rejected.
- No telemetry.

Out of scope: reports about defeating certificate verification on third-party devices. That is
something Modigliani deliberately never does.

Dependencies are checked with `pip-audit` and `govulncheck` on every push, and CodeQL analyzes
the Python and Go code.
