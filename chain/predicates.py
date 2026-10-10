"""Field predicates for `where:` clauses, plus behavioral baselines (`rare:`)."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .schema import Event, Trust


def _as_list(v: Any) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _coerce(path: str, v: Any) -> Any:
    if path == "trust" and not isinstance(v, Trust):
        return Trust.parse(v)
    return v


def check_value(path: str, actual: Any, cond: Any) -> bool:
    """Evaluate one field condition. Lists in the condition mean 'any of'."""
    if isinstance(cond, dict):
        return all(_op(path, actual, op, arg) for op, arg in cond.items())
    if isinstance(cond, list):
        wanted = {_coerce(path, c) for c in cond}
        return any(a in wanted for a in _as_list(actual)) if isinstance(actual, (list, tuple, set)) \
            else actual in wanted
    cond = _coerce(path, cond)
    if isinstance(actual, (list, tuple, set)):
        return cond in actual
    return actual == cond


def _op(path: str, actual: Any, op: str, arg: Any) -> bool:
    if op == "exists":
        return (actual is not None) == bool(arg)
    if actual is None:
        return False
    if op == "eq":
        return actual == _coerce(path, arg)
    if op == "ne":
        return actual != _coerce(path, arg)
    if op == "in":
        return check_value(path, actual, list(_as_list(arg)))
    if op == "not_in":
        return not check_value(path, actual, list(_as_list(arg)))
    if op == "contains":
        return any(str(a).lower() in str(actual).lower() for a in _as_list(arg))
    if op == "contains_all":
        items = actual if isinstance(actual, (list, tuple, set)) else [actual]
        return all(any(str(a).lower() in str(i).lower() for i in items) for a in _as_list(arg))
    if op == "regex":
        return re.search(arg, str(actual), re.I) is not None
    if op in ("gt", "gte", "lt", "lte"):
        a, b = _coerce(path, actual), _coerce(path, arg)
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "max":   # trust: {max: external}  -> trust <= EXTERNAL
        return _coerce(path, actual) <= _coerce(path, arg)
    if op == "min":
        return _coerce(path, actual) >= _coerce(path, arg)
    raise ValueError(f"unknown operator {op!r} on {path}")


class BaselineStore:
    """Counts how often a value is seen per entity. Powers `rare:` predicates.

    In production back this with Redis / a time-decayed sketch per tenant.
    """

    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, Any, Any], int] = defaultdict(int)

    def seen(self, by: str, field: str, by_val: Any, val: Any) -> int:
        return self._counts[(by, field, by_val, _hashable(val))]

    def observe(self, event: Event, keys: list[tuple[str, str]]) -> None:
        for by, field in keys:
            by_val, val = event.get(by), event.get(field)
            if val is not None:
                self._counts[(by, field, by_val, _hashable(val))] += 1


def _hashable(v: Any) -> Any:
    return tuple(v) if isinstance(v, list) else v


def check_where(event: Event, where: dict[str, Any], baseline: BaselineStore | None = None) -> tuple[bool, list[str]]:
    """Return (matched, evidence lines)."""
    evidence: list[str] = []
    for path, cond in where.items():
        if path == "rare":
            if baseline is None:
                return False, evidence
            by, field = cond.get("by", "host"), cond["field"]
            n = baseline.seen(by, field, event.get(by), event.get(field))
            if n > cond.get("max_seen", 0):
                return False, evidence
            evidence.append(f"rare: {field}={event.get(field)!r} seen {n}x for {by}={event.get(by)!r}")
            continue
        if path == "sigma":
            from .importers.sigma import SigmaDetection

            det = cond if isinstance(cond, SigmaDetection) else SigmaDetection(cond["detection"])
            if not det.matches(event):
                return False, evidence
            evidence.append("sigma detection matched")
            continue
        actual = event.get(path)
        if not check_value(path, actual, cond):
            return False, evidence
        shown = actual.name.lower() if isinstance(actual, Trust) else actual
        evidence.append(f"{path}={shown!r}")
    return True, evidence
