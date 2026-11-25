"""Regenerate docs/profile.schema.json from the pydantic profile model."""

from __future__ import annotations

import json
from pathlib import Path

from modigliani.profile.validate import json_schema

OUT = Path(__file__).resolve().parents[1] / "docs" / "profile.schema.json"

if __name__ == "__main__":
    OUT.write_text(json.dumps(json_schema(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")
