"""Safety checks for imported rules.

Upstream rule sets are written for other engines and reviewed to other
standards. Before a converted rule enters the corpus it is checked for the
failure modes that hurt most in production:

- a regex that backtracks catastrophically (one event can stall the engine)
- a rule that matches everything (fires on an empty event of its own type)
- a step with no constraint at all

Flags don't block the import; they are recorded in the report and in the
rule's origin notes so a reviewer sees them, and `chain sources sync
--strict` can refuse them.
"""
from __future__ import annotations

import re
import time
from typing import Any, Iterator

from ..engine import Engine
from ..rules import CompiledRule
from ..schema import Event

# Nested quantifiers like (a+)+ or (\w*)* are the classic exponential case.
NESTED_QUANT = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
# Probe inputs: one short one that explodes exponential patterns, one long one for quadratic ones.
PROBES = ["a" * 24 + "!", "aaaa bbbb " * 200 + "!", "\\" * 24 + "x", "x" * 23 + "\n" + "x" * 23]
SLOW_SECONDS = 0.05


def _regexes(rule: CompiledRule) -> Iterator[tuple[str, str]]:
    """Every regex the rule will run, with where it came from."""
    for step in rule.steps:
        spec = step.spec
        det = (spec.where.get("sigma") or {}).get("detection", {}) if isinstance(spec.where.get("sigma"), dict) else {}
        for name, sel in det.items():
            if name in ("condition", "timeframe"):
                continue
            for item in (sel if isinstance(sel, list) else [sel]):
                if not isinstance(item, dict):
                    continue
                for key, expected in item.items():
                    if "|re" in key:
                        for v in (expected if isinstance(expected, list) else [expected]):
                            yield str(v), f"{spec.name}.{key}"
        for path, cond in spec.where.items():
            if isinstance(cond, dict) and "regex" in cond:
                yield str(cond["regex"]), f"{spec.name}.{path}"
        if spec.match:
            yield from _match_regexes(spec.match, spec.name)


def _match_regexes(node: dict[str, Any], where: str) -> Iterator[tuple[str, str]]:
    for key in ("any", "all"):
        for child in node.get(key, []) or []:
            if "regex" in child:
                yield str(child["regex"]), f"{where}.match"
            elif "any" in child or "all" in child:
                yield from _match_regexes(child, where)


def check_regex(pattern: str) -> str | None:
    """Return a reason if the pattern looks dangerous, else None."""
    try:
        compiled = re.compile(pattern, re.I)
    except re.error as e:
        return f"invalid regex: {e}"
    if NESTED_QUANT.search(pattern):
        return "nested quantifier (possible catastrophic backtracking)"
    for probe in PROBES:
        t0 = time.perf_counter()
        compiled.search(probe)
        if time.perf_counter() - t0 > SLOW_SECONDS:
            return f"slow on a {len(probe)}-char probe (possible catastrophic backtracking)"
    return None


def _blank_events(rule: CompiledRule) -> list[Event]:
    """Empty-ish events of the types the rule's first step accepts."""
    types = rule.steps[0].spec.event
    out = []
    for t in types:
        concrete = t.replace("*", "x") if "*" in t else t
        out.append(Event(type=concrete, host="h", user="u", session_id="s"))
        out.append(Event(type=concrete, host="h", user="u", session_id="s", fields={"message": ""}))
    return out


def check_rule(rule: CompiledRule) -> list[str]:
    """All safety flags for one compiled rule."""
    flags: list[str] = []
    seen: set[str] = set()
    for pattern, where in _regexes(rule):
        if pattern in seen:
            continue
        seen.add(pattern)
        reason = check_regex(pattern)
        if reason:
            flags.append(f"regex at {where}: {reason}")

    for step in rule.steps:
        spec = step.spec
        unconstrained = not spec.where and not spec.match and not spec.count and not spec.absent
        if unconstrained and spec.event == ["*"]:
            flags.append(f"step {spec.name} has no event type and no constraint")

    if len(rule.steps) == 1 and not rule.steps[0].spec.count and not rule.steps[0].spec.absent:
        try:
            eng = Engine([rule])
            if any(eng.evaluate(e).hits for e in _blank_events(rule)):
                flags.append("matches an empty event of its own type")
        except Exception as e:  # noqa: BLE001 - evaluation errors are themselves a flag
            flags.append(f"evaluation error on an empty event: {type(e).__name__}: {e}")
    return flags
