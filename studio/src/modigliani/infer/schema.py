"""JSON Schema inference for message bodies (via genson).

Schemas describe types, never values, so they are safe to share without scrubbing.
"""

from __future__ import annotations

from typing import Any, cast

from genson import SchemaBuilder


def infer_schema(samples: list[Any]) -> dict[str, Any] | None:
    samples = [s for s in samples if s is not None]
    if not samples:
        return None
    builder = SchemaBuilder()
    for s in samples:
        builder.add_object(s)
    schema = cast(dict[str, Any], builder.to_schema())
    schema.pop("$schema", None)
    return schema
