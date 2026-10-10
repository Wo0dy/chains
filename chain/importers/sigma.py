r"""Sigma compatibility: evaluate Sigma detections natively and convert Sigma rules to Chain.

Supported: selections (maps = AND, lists of maps = OR), keyword lists,
wildcards with Sigma escaping (`\*`, `\?`, `\\`), modifiers contains /
startswith / endswith / re / all / base64 / windash / cidr / exists / cased,
conditions with and / or / not / parentheses / `1 of x*` / `all of x*` / `them`.

Everything else is reported, not ignored: `sigma_import` returns the Chain
rule plus a list of fidelity notes naming each feature that was dropped or
approximated, so the corpus can label the rule `exact` or `lossy`.

Not yet: aggregation (`| count() > n`) and correlation rules - express those
as Chain sequences (roadmap Phase B).
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import yaml

from ..schema import Event

# Sigma logsource category -> Chain event type. A category not listed here
# maps to `<product>.<category>` so the rule still only sees its own log type.
LOGSOURCE_TO_TYPE = {
    "application": "log.{product}.application",
    "database": "log.{product}.database",
    "appliance": "log.{product}.appliance",
    "process_creation": "process.start",
    "process_access": "process.access",
    "process_termination": "process.exit",
    "process_tampering": "process.tamper",
    "image_load": "process.image_load",
    "create_remote_thread": "process.remote_thread",
    "raw_access_thread": "process.raw_access",
    "driver_load": "process.driver_load",
    "network_connection": "net.flow",
    "dns_query": "net.dns",
    "dns": "net.dns",
    "firewall": "net.firewall",
    "proxy": "net.proxy",
    "webserver": "net.http",
    "file_event": "file.create",
    "file_change": "file.change",
    "file_delete": "file.delete",
    "file_rename": "file.rename",
    "file_access": "file.access",
    "file_executable_detected": "file.exec",
    "file_block": "file.block",
    "create_stream_hash": "file.stream",
    "registry_event": "registry.event",
    "registry_set": "registry.set",
    "registry_add": "registry.add",
    "registry_delete": "registry.delete",
    "pipe_created": "ipc.pipe",
    "wmi_event": "wmi.event",
    "ps_script": "powershell.script",
    "ps_module": "powershell.module",
    "ps_classic_start": "powershell.start",
    "ps_classic_provider_start": "powershell.provider",
    "antivirus": "av.detection",
    "clipboard_capture": "host.clipboard",
    "sysmon_status": "host.sysmon",
    "sysmon_error": "host.sysmon",
}

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "base64", "windash", "cidr", "exists", "cased"}
# Modifiers Sigma defines that the native evaluator doesn't implement yet.
KNOWN_UNSUPPORTED = {
    "base64offset", "utf16le", "utf16be", "utf16", "wide", "gt", "gte", "lt", "lte",
    "expand", "fieldref", "i", "m", "s", "minute", "hour", "day", "week", "month", "year",
}

_WINDASH = ("-", "/", "–", "—", "―")
_WILD = set("*?\\")


@lru_cache(maxsize=65536)
def _glob(value: str, mode: str, cased: bool) -> re.Pattern[str]:
    r"""Sigma value with wildcards -> regex. `\*` and `\?` are literal, `\\` is one backslash,
    any other backslash is literal too (so Windows paths need no escaping)."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(out)
    if mode == "contains":
        pat = body
    elif mode == "startswith":
        pat = "^" + body
    elif mode == "endswith":
        pat = body + r"\Z"
    else:
        pat = "^" + body + r"\Z"
    return re.compile(pat, 0 if cased else re.I | re.S)


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
    if "exists" in mods:
        return (actual is not None) == (str(expected).lower() == "true")
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
    if "windash" in mods:
        variants = [e]
        for ch in _WINDASH:
            variants += [v.replace("-", ch) for v in variants if "-" in v]
        return any(_match_one(a, v, [m for m in mods if m != "windash"]) for v in dict.fromkeys(variants))
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(a.strip()) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "equals")
    cased = "cased" in mods
    if _WILD & set(e):
        return _glob(e, mode, cased).search(a) is not None
    if not cased:
        a, e = a.lower(), e.lower()
    if mode == "contains":
        return e in a
    if mode == "startswith":
        return a.startswith(e)
    if mode == "endswith":
        return a.endswith(e)
    return a == e


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


# ------------------------------------------------------------------ import

class SigmaUnsupported(ValueError):
    """The rule can't be represented in Chain yet (aggregation, correlation ...)."""


@dataclass
class SigmaImport:
    rule: dict[str, Any]
    notes: list[str] = field(default_factory=list)   # fidelity notes; empty = exact
    meta: dict[str, Any] = field(default_factory=dict)  # upstream metadata worth keeping


def _event_type(logsource: dict[str, Any], notes: list[str]) -> str | None:
    category = logsource.get("category")
    product = logsource.get("product")
    service = logsource.get("service")
    if category in LOGSOURCE_TO_TYPE:
        return LOGSOURCE_TO_TYPE[category].format(product=product or "generic")
    if category:
        # Convention for categories without a schema type: the rule still only sees its own log type.
        return f"{product or 'log'}.{category}"
    if service:
        return f"log.{product or 'generic'}.{service}"
    if product:
        return f"log.{product}.*"
    notes.append("no logsource; rule applies to every event type")
    return None


def _walk_detection(detection: dict[str, Any], notes: list[str]) -> None:
    """Record every feature the native evaluator approximates or ignores."""
    seen_unsupported: set[str] = set()
    for name, sel in detection.items():
        if name in ("condition", "timeframe"):
            continue
        items = sel if isinstance(sel, list) else [sel]
        for item in items:
            if not isinstance(item, dict):
                continue
            for key, expected in item.items():
                _, *mods = key.split("|")
                for m in mods:
                    if m in SUPPORTED_MODIFIERS:
                        continue
                    if m not in seen_unsupported:
                        seen_unsupported.add(m)
                        kind = "unsupported" if m in KNOWN_UNSUPPORTED else "unknown"
                        notes.append(f"{kind} modifier |{m} ignored (field {key})")
                values = expected if isinstance(expected, list) else [expected]
                if "re" in mods:
                    for v in values:
                        try:
                            re.compile(str(v))
                        except re.error as e:
                            raise SigmaUnsupported(f"invalid regex in {key}: {e}") from e
    if detection.get("timeframe") is not None:
        notes.append("timeframe without aggregation ignored")


def sigma_import(sigma: dict[str, Any] | str) -> SigmaImport:
    """Convert a Sigma rule into a Chain rule and report what was lost on the way."""
    if isinstance(sigma, str):
        docs = [d for d in yaml.safe_load_all(sigma) if d]
        if len(docs) != 1:
            raise SigmaUnsupported("multi-document rule collection")
        sigma = docs[0]
    if "correlation" in sigma:
        raise SigmaUnsupported("correlation rule")
    if "detection" not in sigma:
        raise SigmaUnsupported("no detection block")
    detection = sigma["detection"]
    if "|" in str(detection.get("condition", "")):
        raise SigmaUnsupported("aggregation in condition")

    notes: list[str] = []
    _walk_detection(detection, notes)
    logsource = sigma.get("logsource") or {}
    event_type = _event_type(logsource, notes)
    level = sigma.get("level", "medium")

    step: dict[str, Any] = {"name": "match", "where": {"sigma": {"detection": detection}}}
    if event_type:
        step["event"] = event_type
    rule = {
        "id": "sigma_" + re.sub(r"[^a-z0-9]+", "_", str(sigma.get("id") or sigma.get("title", "rule")).lower()).strip("_"),
        "title": sigma.get("title", ""),
        "description": str(sigma.get("description", "") or ""),
        "severity": {"informational": "info", "critical": "critical"}.get(level, level),
        "action": "alert",
        "tags": list(sigma.get("tags", []) or []) + ["imported:sigma"],
        "sequence": [step],
    }
    meta = {
        "upstream_id": str(sigma.get("id", "")),
        "status": sigma.get("status"),
        "logsource": dict(logsource),
        "falsepositives": list(sigma.get("falsepositives", []) or []),
        "references": list(sigma.get("references", []) or []),
        "author": sigma.get("author"),
        "date": str(sigma.get("date", "") or ""),
        "modified": str(sigma.get("modified", "") or ""),
    }
    return SigmaImport(rule, notes, meta)


def sigma_to_chain(sigma: dict[str, Any] | str) -> dict[str, Any]:
    """Convert a Sigma rule (dict or YAML string) into a Chain rule dict."""
    return sigma_import(sigma).rule
