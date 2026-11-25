"""Print the CHANGELOG.md section for a version (used for GitHub Release notes)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parents[1] / "CHANGELOG.md"


def section(version: str, text: str) -> str:
    out: list[str] = []
    inside = False
    for line in text.splitlines():
        if re.match(r"^## \[", line):
            if inside:
                break
            inside = line.startswith(f"## [{version}]")
            continue
        if inside:
            out.append(line)
    if not inside and not out:
        raise SystemExit(f"CHANGELOG.md has no section for {version}")
    return "\n".join(out).strip() + "\n"


if __name__ == "__main__":
    print(section(sys.argv[1], CHANGELOG.read_text(encoding="utf-8")), end="")
