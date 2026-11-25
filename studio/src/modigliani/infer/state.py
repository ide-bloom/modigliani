"""State model: correlate the user's annotations with fields that change in traffic.

Rules (docs/inference.md, "State model"):
- Command rule: after an action annotation with value V, a cloud-to-device field that carries
  V within the window [t-2s, t+15s] is a command encoding for that variable.
- Report rule: a device-to-cloud field whose value becomes V within [t, t+30s] reports the
  variable's state. Fields that already carried V just before t score lower.
- Reading rule: a reading annotation ("app shows 21.5 C") marks the device-to-cloud field that
  carries the value (possibly scaled by 10, 100 or 2) as a sensor.
- Name rule (no annotations needed): a cloud-to-device field whose name equals a reported field
  name is a command for that variable.
- Variation rule: unannotated device-to-cloud fields that vary become read-only sensors, except
  counters and timestamps.
"""

from __future__ import annotations

import itertools
import json
import math
from collections import defaultdict
from dataclasses import dataclass, field

from modigliani.annotate.model import Annotation, AnnotationKind
from modigliani.capture.model import Direction
from modigliani.infer.sessions import Ref
from modigliani.infer.values import Scalar, leaf_name, snake, time_kind

COMMAND_WINDOW = (-2.0, 15.0)
REPORT_WINDOW = (0.0, 30.0)
_SCALES = (1.0, 0.1, 0.01, 0.5)
_TRUE_STRINGS = {"on", "true", "1", "yes", "open", "enabled", "enable"}
_FALSE_STRINGS = {"off", "false", "0", "no", "closed", "close", "disabled", "disable"}
_COUNTER_NAMES = ("uptime", "seq", "counter", "count", "ts", "time", "epoch", "timestamp", "ms", "msg_id", "id")


@dataclass
class Obs:
    ts: float
    value: Scalar
    ref: Ref


@dataclass
class FieldSeries:
    """All values one field took, e.g. channel 'mqtt:telemetry' path 'setpoint'."""

    channel: str
    path: str
    dir: Direction
    obs: list[Obs] = field(default_factory=list)
    # Optional human name (binary fields are named from annotation hints).
    name: str | None = None

    @property
    def values(self) -> list[Scalar]:
        return [o.value for o in self.obs]

    @property
    def key(self) -> tuple[str, str]:
        return self.channel, self.path


@dataclass
class ValueMatch:
    scale: float | None = None
    # device value (JSON text) -> state value, when the device encodes e.g. booleans as "on"/"off"
    value_map: dict[str, Scalar] | None = None


def match_value(device_value: Scalar, target: Scalar) -> ValueMatch | None:
    """Does a device value encode the annotated value? Returns how, or None."""
    if device_value is None or target is None:
        return None
    if isinstance(target, bool):
        if isinstance(device_value, bool):
            return ValueMatch() if device_value == target else None
        if isinstance(device_value, int | float) and device_value in (0, 1):
            if bool(device_value) == target:
                return ValueMatch(value_map={"1": True, "0": False})
            return None
        if isinstance(device_value, str):
            low = device_value.lower()
            if (target and low in _TRUE_STRINGS) or (not target and low in _FALSE_STRINGS):
                on, off = _pair_for(low)
                return ValueMatch(value_map={json.dumps(on): True, json.dumps(off): False})
        return None
    if isinstance(target, int | float):
        dv: float | None = None
        if isinstance(device_value, bool):
            return None
        if isinstance(device_value, int | float):
            dv = float(device_value)
        elif isinstance(device_value, str):
            try:
                dv = float(device_value)
            except ValueError:
                return None
        for scale in _SCALES:
            if math.isclose(dv * scale, float(target), rel_tol=1e-6, abs_tol=1e-6):
                return ValueMatch(scale=None if scale == 1.0 else scale)
        return None
    if isinstance(device_value, str) and isinstance(target, str):
        return ValueMatch() if device_value.lower() == target.lower() else None
    return None


def _pair_for(word: str) -> tuple[str, str]:
    pairs = [
        ("on", "off"),
        ("true", "false"),
        ("1", "0"),
        ("yes", "no"),
        ("open", "closed"),
        ("enabled", "disabled"),
        ("enable", "disable"),
    ]
    for on, off in pairs:
        if word in (on, off):
            return on, off
    return "on", "off"


@dataclass
class VariableEvidence:
    name: str
    kind: str  # "bool" | "number" | "enum" | "string"
    writable: bool
    report: FieldSeries | None = None
    report_match: ValueMatch | None = None
    command: FieldSeries | None = None
    command_match: ValueMatch | None = None
    unit: str | None = None
    annotated_values: list[Scalar] = field(default_factory=list)
    refs: list[Ref] = field(default_factory=list)
    confidence: str = "annotation"


def _hint_words(ann: Annotation) -> set[str]:
    return set(snake(ann.variable).split("_")) if ann.variable else set()


def _name_bonus(series: FieldSeries, words: set[str]) -> float:
    if not words:
        return 0.0
    name = (series.name or leaf_name(series.path)).split("_")
    return 0.5 if words & set(name) else 0.0


def _binary_valued(series: FieldSeries) -> bool:
    for v in series.values:
        if isinstance(v, bool) or v in (0, 1):
            continue
        if isinstance(v, str) and v.lower() in _TRUE_STRINGS | _FALSE_STRINGS:
            continue
        return False
    return True


def _value_at(series: FieldSeries, start: float, end: float, target: Scalar) -> tuple[Obs, ValueMatch] | None:
    # A boolean action can only be encoded by a field that only ever holds two-state values.
    if isinstance(target, bool) and not _binary_valued(series):
        return None
    for o in series.obs:
        if start <= o.ts <= end and (m := match_value(o.value, target)) is not None:
            return o, m
    return None


def _value_before(series: FieldSeries, ts: float) -> Scalar:
    before = [o for o in series.obs if o.ts < ts]
    return before[-1].value if before else None


def _group_annotations(annotations: list[Annotation]) -> dict[str, list[Annotation]]:
    """Annotations about the same variable: same hint, else same value kind (+unit)."""
    groups: dict[str, list[Annotation]] = defaultdict(list)
    for a in annotations:
        if a.value is None:
            continue
        if a.variable:
            key = "hint:" + snake(a.variable)
        elif isinstance(a.value, bool):
            key = "bool"
        elif isinstance(a.value, int | float):
            key = f"number:{a.unit or ''}"
        else:
            key = "enum"
        groups[f"{a.kind}:{key}"].append(a)
    return groups


def _kind_of(values: list[Scalar]) -> str:
    vals = [v for v in values if v is not None]
    if vals and all(isinstance(v, bool) for v in vals):
        return "bool"
    if vals and all(isinstance(v, int | float) and not isinstance(v, bool) for v in vals):
        return "number"
    return "enum" if len({str(v) for v in vals}) <= 8 else "string"


def is_counter_or_time(series: FieldSeries, ref_ts: float) -> bool:
    vals = series.values
    if any(time_kind(v, ref_ts) for v in vals[:3]):
        return True
    nums = [v for v in vals if isinstance(v, int | float) and not isinstance(v, bool)]
    if len(nums) >= 3 and len(nums) == len(vals):
        increasing = all(b >= a for a, b in itertools.pairwise(nums)) and nums[-1] > nums[0]
        name = (series.name or leaf_name(series.path)).lower()
        named = any(n == name or name.endswith("_" + n) for n in _COUNTER_NAMES)
        # An integer that never repeats and never falls is a counter; a float that rises is a reading.
        distinct_ints = all(isinstance(n, int) for n in nums) and len(set(nums)) == len(nums)
        if increasing and (named or distinct_ints):
            return True
    return False


def correlate(
    series: list[FieldSeries],
    annotations: list[Annotation],
    ref_ts: float,
    excluded: set[tuple[str, str]] | None = None,
) -> list[VariableEvidence]:
    excluded = excluded or set()
    # Counters and clocks change on their own; they must never explain a user action.
    usable = [s for s in series if s.key not in excluded and not is_counter_or_time(s, ref_ts)]
    ups = [s for s in usable if s.dir is Direction.UP]
    downs = [s for s in usable if s.dir is Direction.DOWN]
    variables: list[VariableEvidence] = []
    used_up: set[tuple[str, str]] = set()
    used_down: set[tuple[str, str]] = set()

    for _key, anns in sorted(_group_annotations(annotations).items()):
        words = set().union(*(_hint_words(a) for a in anns))
        is_reading = anns[0].kind is AnnotationKind.READING
        best_up: tuple[float, FieldSeries, ValueMatch, list[Ref]] | None = None
        for s in ups:
            if s.key in used_up:
                continue
            score, match, refs = 0.0, None, []
            for a in anns:
                lo, hi = (
                    (a.ts - 10.0, a.ts + 10.0) if is_reading else (a.ts + REPORT_WINDOW[0], a.ts + REPORT_WINDOW[1])
                )
                hit = _value_at(s, lo, hi, a.value)
                if hit:
                    changed = is_reading or match_value(_value_before(s, a.ts), a.value) is None
                    score += 1.0 if changed else 0.4
                    match = match or hit[1]
                    refs.append(hit[0].ref)
            if match is None:
                continue
            score += _name_bonus(s, words)
            if best_up is None or score > best_up[0]:
                best_up = (score, s, match, refs)
        best_down: tuple[float, FieldSeries, ValueMatch, list[Ref]] | None = None
        if not is_reading:
            for s in downs:
                if s.key in used_down:
                    continue
                score, match, refs = 0.0, None, []
                for a in anns:
                    hit = _value_at(s, a.ts + COMMAND_WINDOW[0], a.ts + COMMAND_WINDOW[1], a.value)
                    if hit:
                        score += 1.0
                        match = match or hit[1]
                        refs.append(hit[0].ref)
                if match is None:
                    continue
                score += _name_bonus(s, words)
                if best_down is None or score > best_down[0]:
                    best_down = (score, s, match, refs)
        need = max(1.0, len(anns) / 2)
        up_ok = best_up is not None and best_up[0] >= need
        down_ok = best_down is not None and best_down[0] >= need
        if not up_ok and not down_ok:
            continue
        hint = next((snake(a.variable) for a in anns if a.variable), None)
        if up_ok and best_up is not None:
            base = best_up[1].name or leaf_name(best_up[1].path)
        elif best_down is not None:
            base = best_down[1].name or leaf_name(best_down[1].path)
        else:
            base = hint or "value"
        if base.startswith(("field_", "const_")) and hint:
            base = hint
        if base == "value" and hint:
            base = hint
        if hint is None and isinstance(anns[0].value, bool) and base in ("value", "state", "on"):
            base = "power"
        values = [a.value for a in anns]
        var = VariableEvidence(
            name=base,
            kind=_kind_of(values),
            writable=down_ok and not is_reading,
            unit=next((a.unit for a in anns if a.unit), None),
            annotated_values=values,
        )
        if up_ok and best_up is not None:
            var.report, var.report_match = best_up[1], best_up[2]
            var.refs += best_up[3]
            used_up.add(best_up[1].key)
        if down_ok and best_down is not None:
            var.command, var.command_match = best_down[1], best_down[2]
            var.refs += best_down[3]
            used_down.add(best_down[1].key)
        variables.append(var)

    # Name rule: a down field named like a reported field is a command for it.
    names = {v.report.key: v for v in variables if v.report}
    for s in downs:
        if s.key in used_down:
            continue
        leaf = s.name or leaf_name(s.path)
        for up in ups:
            if (up.name or leaf_name(up.path)) == leaf and _kind_of(up.values) == _kind_of(s.values):
                existing = names.get(up.key)
                if existing is None:
                    existing = VariableEvidence(
                        name=leaf,
                        kind=_kind_of(up.values),
                        writable=True,
                        report=up,
                        report_match=ValueMatch(),
                        confidence="name",
                    )
                    variables.append(existing)
                    names[up.key] = existing
                    used_up.add(up.key)
                if existing.command is None:
                    existing.command, existing.command_match = s, ValueMatch()
                    existing.writable = True
                    used_down.add(s.key)
                break

    # Variation rule: remaining varying device-to-cloud fields become read-only sensors.
    for s in ups:
        if s.key in used_up:
            continue
        distinct = {json.dumps(v) for v in s.values}
        if len(distinct) < 2 or is_counter_or_time(s, ref_ts):
            continue
        kind = _kind_of(s.values)
        if kind == "string":
            continue
        variables.append(
            VariableEvidence(
                name=s.name or leaf_name(s.path),
                kind=kind,
                writable=False,
                report=s,
                report_match=ValueMatch(),
                confidence="variation",
                refs=[o.ref for o in s.obs[:3]],
            )
        )
        used_up.add(s.key)

    # Unique names.
    seen: dict[str, int] = {}
    for v in variables:
        if v.name in seen:
            seen[v.name] += 1
            v.name = f"{v.name}_{seen[v.name]}"
        else:
            seen[v.name] = 1
    return variables
