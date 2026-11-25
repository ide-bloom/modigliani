# Contributing

Thank you for helping revive orphaned devices. Code, profiles, documentation and bug reports are
all welcome.

## Development setup

You need Python 3.12+ with [uv](https://docs.astral.sh/uv/), Go (the version in
`server/go.mod`) and Git. Npcap is only needed for live capture on Windows.

```powershell
uv sync                                   # Studio + dev tools
uv run modigliani --help
cd server; go build ./...; cd ..
```

Keep build output out of the repository. The `.gitignore` covers `bin/`, `dist/`, `build/`,
captures, CA keys and `profiles/local/`. Never commit captures, CA keys, unscrubbed profiles or
token-shaped literals. Test fixtures must be synthetic: they are generated at test time.

## Checks (all run in CI on Linux and Windows)

```powershell
uv run ruff check studio/src tests scripts homeassistant
uv run ruff format --check studio/src tests scripts homeassistant
uv run mypy                                # strict
uv run pytest tests/unit
uv run pip-audit --skip-editable
cd server
go vet ./...
go test -race ./...                        # the race detector needs a C compiler (cgo)
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
cd ..
# End to end: builds the server into a temporary directory
uv run pytest tests/e2e
# Home Assistant integration (Linux/macOS; Home Assistant does not run on Windows)
cd homeassistant; uv venv .venv; uv pip install --python .venv -r requirements_test.txt; .venv/bin/python -m pytest
```

If you change the profile model, regenerate the schema with
`uv run python scripts/gen_schema.py`.

## Code standards

- Python: full type hints, `mypy --strict`, pydantic models for every external format.
- Go: idiomatic, `context.Context` everywhere, no global state, structured logging with `slog`.
- Every inference rule needs a test and a description in `docs/inference.md`.
- Comments explain *why*, not *what*.
- Respect the scope: Modigliani works only with devices the user owns, never defeats certificate
  verification, never modifies firmware, and never sends crafted traffic to vendors.

## Contributing a profile

1. Record and infer your device. Check it with `modigliani test` and `modigliani review`.
2. `modigliani export profiles/local/<id>.yaml --share --license CC0-1.0` (or `CC-BY-4.0`
   with `--author`). Read the scrub diff carefully, especially binary `const_*` fields.
3. Open a pull request adding `profiles/library/<id>.yaml` and its `.sig`. Include your public
   key (`modigliani keygen` prints it) in the description.

## Commits and pull requests

Keep pull requests focused, describe how you tested them, and update `CHANGELOG.md` under
*Unreleased*. By contributing you agree that code is licensed under Apache-2.0, and profiles
under the CC license you choose.
