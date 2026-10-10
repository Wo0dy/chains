"""Sigma compatibility: evaluate Sigma detections natively and convert Sigma rules to Chain.

Supported: selections (maps = AND, lists of maps = OR), keyword lists,
modifiers contains / startswith / endswith / re / all / base64 / cidr-less,
conditions with and / or / not / parentheses / `1 of x*` / `all of x*` / `them`.
Not yet: aggregation (`| count() > n`) - express those as Chain sequences.
"""
from __future__ import annotations

import base64
import fnmatch
import re
from typing import Any

import yaml

from ..schema import Event

LOGSOURCE_TO_TYPE = {
    "process_creation": "process.start",
    "network_connection": "net.flow",
    "dns_query": "net.dns",
    "file_event": "file.create",
    "image_load": "process.image_load",
}


def _field_value(event: Event, field: str) -> Any:
    if field in event.fields:
        return event.fields[field]
    # case-insensitive fallback, then schema path
    low = field.lower()
    for k, v in event.fields.items():
        if k.lower() == low:
            return v
    return event.get(field)


def _match_one(actual: Any, expected: Any, mods: list[str]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)
    if "base64" in mods:
        e = base64.b64encode(e.encode()).decode()
    if "re" in mods:
        return re.search(e, a) is not None
    a_low, e_low = a.lower(), e.lower()
    if "contains" in mods:
        return e_low in a_low
    if "startswith" in mods:
        return a_low.startswith(e_low)
    if "endswith" in mods:
        return a_low.endswith(e_low)
    if "*" in e_low or "?" in e_low:
        return fnmatch.fnmatchcase(a_low, e_low)
    return a_low == e_low


def _match_selection(event: Event, sel: Any) -> bool:
    if isinstance(sel, list):
        if all(isinstance(x, (str, int)) for x in sel):          # keyword search
            text = event.text.lower()
            return any(str(k).lower() in text for k in sel)
        return any(_match_selection(event, s) for s in sel)     # list of maps = OR
    if isinstance(sel, dict):
        for key, expected in sel.items():                        # map = AND
            field, *mods = key.split("|")
            actual = _field_value(event, field)
            values = expected if isinstance(expected, list) else [expected]
            fn = all if "all" in mods else any
            if not fn(_match_one(actual, v, mods) for v in values):
                return False
        return True
    return False


class SigmaDetection:
    def __init__(self, detection: dict[str, Any]) -> None:
        detection = dict(detection)
        self.condition = str(detection.pop("condition", "selection"))
        self.timeframe = detection.pop("timeframe", None)
        self.selections = detection
        if "|" in self.condition:
            raise NotImplementedError("Sigma aggregations: rewrite as a Chain sequence rule")
        self._tokens = re.findall(r"\(|\)|[^\s()]+", self.condition)

    def matches(self, event: Event) -> bool:
        cache: dict[str, bool] = {}

        def sel(name: str) -> bool:
            if name not in cache:
                cache[name] = _match_selection(event, self.selections[name])
            return cache[name]

        tokens = list(self._tokens)
        pos = 0

        def peek() -> str | None:
            return tokens[pos] if pos < len(tokens) else None

        def take() -> str:
            nonlocal pos
            pos += 1
            return tokens[pos - 1]

        def expr() -> bool:
            val = term()
            while peek() == "or":
                take()
                rhs = term()
                val = val or rhs
            return val

        def term() -> bool:
            val = factor()
            while peek() == "and":
                take()
                rhs = factor()
                val = val and rhs
            return val

        def factor() -> bool:
            tok = take()
            if tok == "not":
                return not factor()
            if tok == "(":
                val = expr()
                take()  # ')'
                return val
            if tok in ("1", "all") and peek() == "of":
                take()
                pattern = take()
                names = list(self.selections) if pattern == "them" else \
                    [n for n in self.selections if fnmatch.fnmatchcase(n, pattern)]
                results = [sel(n) for n in names]
                return any(results) if tok == "1" else (all(results) and bool(results))
            return sel(tok)

        return expr()


def sigma_to_chain(sigma: dict[str, Any] | str) -> dict[str, Any]:
    """Convert a Sigma rule (dict or YAML string) into a Chain rule dict."""
    if isinstance(sigma, str):
        sigma = yaml.safe_load(sigma)
    logsource = sigma.get("logsource", {})
    category = logsource.get("category", "")
    level = sigma.get("level", "medium")
    step: dict[str, Any] = {"name": "match", "where": {"sigma": {"detection": sigma["detection"]}}}
    if category in LOGSOURCE_TO_TYPE:
        step["event"] = LOGSOURCE_TO_TYPE[category]
    return {
        "id": "sigma_" + re.sub(r"[^a-z0-9]+", "_", str(sigma.get("id") or sigma.get("title", "rule")).lower()).strip("_"),
        "title": sigma.get("title", ""),
        "description": sigma.get("description", ""),
        "severity": {"informational": "info", "critical": "critical"}.get(level, level),
        "action": "alert",
        "tags": list(sigma.get("tags", [])) + ["imported:sigma"],
        "sequence": [step],
    }
