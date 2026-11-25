## What and why

## How it was tested

- [ ] `uv run ruff check`, `uv run mypy`, `uv run pytest tests/unit`
- [ ] `go vet`, `go test -race`, `golangci-lint run` (server changes)
- [ ] `uv run pytest tests/e2e` (capture, inference or server changes)
- [ ] Home Assistant tests (integration changes)

## Checklist

- [ ] Documentation matches the new behavior (README, `docs/`)
- [ ] `CHANGELOG.md` updated under *Unreleased*
- [ ] No captures, CA keys, unscrubbed profiles or token-shaped literals are included
- [ ] New profiles are scrubbed and signed (`modigliani export --share`)
