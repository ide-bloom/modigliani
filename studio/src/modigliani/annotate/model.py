"""Annotations and the parser that turns free-text labels into (variable, value) hints.

Labels are what a person types while using the vendor app ("turned on", "set 22 C",
"mode cool", "app shows temperature 21.5 C"). Inference only needs the value, an
optional variable hint and whether the user *changed* something or *read* something.
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

JsonScalar = bool | int | float | str


class AnnotationKind(StrEnum):
    ACTION = "action"  # the user changed something in the app
    READING = "reading"  # the user read a value shown in the app


class Annotation(BaseModel):
    ts: float = Field(default_factory=time.time)
    label: str
    kind: AnnotationKind = AnnotationKind.ACTION
    variable: str | None = None
    value: JsonScalar | None = None
    unit: str | None = None
    # Which enrolled device the action was about; None applies to every device in the capture.
    device: str | None = None


class AnnotationSet(BaseModel):
    capture: str
    annotations: list[Annotation] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path, capture: str = "") -> AnnotationSet:
        if not path.exists():
            return cls(capture=capture)
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.annotations.sort(key=lambda a: a.ts)
        tmp = path.with_name(path.name + f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        os.replace(tmp, path)

    @classmethod
    def append(
        cls, path: Path, label: str, ts: float | None = None, capture: str = "", device: str | None = None
    ) -> Annotation:
        """Add one annotation safely while other processes (Studio, the CLI) may write too."""
        with _file_lock(path.with_name(path.name + ".lock")):
            anns = cls.load(path, capture)
            ann = anns.add(label, ts, device)
            anns.save(path)
        return ann

    def add(self, label: str, ts: float | None = None, device: str | None = None) -> Annotation:
        ann = parse_label(label, ts if ts is not None else time.time())
        ann.device = device
        self.annotations.append(ann)
        return ann

    def for_device(self, device: str | None) -> list[Annotation]:
        return [a for a in self.annotations if a.device is None or device is None or a.device == device]


_UNITS = {
    "c": "°C",
    "°c": "°C",
    "celsius": "°C",
    "f": "°F",
    "°f": "°F",
    "%": "%",
    "percent": "%",
    "w": "W",
    "watt": "W",
    "watts": "W",
    "kwh": "kWh",
    "v": "V",
    "a": "A",
}
_ON = {"on", "turned on", "turn on", "switch on", "switched on", "enable", "enabled", "open", "opened"}
_OFF = {"off", "turned off", "turn off", "switch off", "switched off", "disable", "disabled", "close", "closed"}
_READING_PREFIX = re.compile(r"^(app\s+)?(shows|show|reads|reading|displays)\s+", re.IGNORECASE)
_EXPLICIT = re.compile(r"^\s*([A-Za-z_][\w.]*)\s*=\s*(.+?)\s*$")
_NUMBER_UNIT = re.compile(r"(-?\d+(?:\.\d+)?)\s*(°?[a-zA-Z%]+)?\s*$")
_FILLER = {"set", "to", "the", "a", "turned", "turn", "switched", "switch", "changed", "change", "at"}


def _coerce(text: str) -> JsonScalar:
    low = text.strip().lower()
    if low in {"true", "on", "yes"}:
        return True
    if low in {"false", "off", "no"}:
        return False
    try:
        return int(low)
    except ValueError:
        pass
    try:
        return float(low)
    except ValueError:
        return text.strip()


def parse_label(label: str, ts: float) -> Annotation:
    """Parse a free-text label. Supports `var=value`, on/off phrases, numbers with units, and words."""
    text = label.strip()
    kind = AnnotationKind.ACTION
    if m := _READING_PREFIX.match(text):
        kind = AnnotationKind.READING
        text = text[m.end() :]

    if m := _EXPLICIT.match(text):
        value = _coerce(m.group(2))
        unit = None
        if isinstance(value, str) and (nm := _NUMBER_UNIT.fullmatch(value)):
            value = _coerce(nm.group(1))
            unit = _UNITS.get((nm.group(2) or "").lower())
        return Annotation(ts=ts, label=label, kind=kind, variable=m.group(1), value=value, unit=unit)

    low = text.lower()
    words = [w for w in re.split(r"\s+", low) if w]
    # "turned on", "led on", "light off": a trailing on/off word is the value.
    if low in _ON or low in _OFF:
        return Annotation(ts=ts, label=label, kind=kind, value=low in _ON)
    if words and words[-1] in {"on", "off"}:
        hint = " ".join(w for w in words[:-1] if w not in _FILLER) or None
        return Annotation(ts=ts, label=label, kind=kind, variable=hint, value=words[-1] == "on")

    if m := _NUMBER_UNIT.search(text):
        value = _coerce(m.group(1))
        unit = _UNITS.get((m.group(2) or "").lower())
        if m.group(2) and unit is None:
            # The trailing token was a word, not a unit (e.g. "set 22 cool"): no unit.
            unit = None
        head = text[: m.start()].strip().lower()
        hint_words = [w for w in re.split(r"\s+", head) if w and w not in _FILLER]
        return Annotation(ts=ts, label=label, kind=kind, variable=" ".join(hint_words) or None, value=value, unit=unit)

    # "mode cool", "set mode to eco": last word is the value, the rest hints the variable.
    meaningful = [w for w in words if w not in _FILLER]
    if len(meaningful) >= 2:
        return Annotation(ts=ts, label=label, kind=kind, variable=" ".join(meaningful[:-1]), value=meaningful[-1])
    if len(meaningful) == 1:
        return Annotation(ts=ts, label=label, kind=kind, value=meaningful[0])
    return Annotation(ts=ts, label=label, kind=kind)


@contextlib.contextmanager
def _file_lock(lock: Path, timeout: float = 10.0) -> Iterator[None]:
    lock.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    while True:
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except (FileExistsError, PermissionError):
            # Windows reports a lock file that is being deleted as PermissionError: also "busy".
            if time.monotonic() > deadline:
                # A crashed writer left the lock behind; annotations are append-only, so proceed.
                lock.unlink(missing_ok=True)
                continue
            time.sleep(0.02)
    try:
        yield
    finally:
        os.close(fd)
        lock.unlink(missing_ok=True)
