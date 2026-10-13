r"""Sigma compatibility: evaluate Sigma detections natively and convert Sigma rules to Chain.

Supported: selections (maps = AND, lists of maps = OR), keyword lists,
wildcards with Sigma escaping (`\*`, `\?`, `\\`), modifiers contains /
startswith / endswith / all / re (with i, m, s flags) / base64 /
base64offset / utf16le / utf16be / utf16 / wide / windash / cidr / exists /
cased / gt / gte / lt / lte / fieldref / expand (with a placeholder map),
conditions with and / or / not / parentheses / `1 of x*` / `all of x*` /
`them`.

Legacy aggregations (`... | count(F) by G > N` with a `timeframe`) convert
to Chain count steps. Correlation rules (event_count, value_count,
temporal, temporal_ordered) convert to Chain sequences; the pipeline
resolves the rules they reference.

Everything else is reported, not ignored: `sigma_import` returns the Chain
rule plus a list of fidelity notes naming each feature that was dropped or
approximated, so the corpus can label the rule `exact` or `lossy`.
"""
from __future__ import annotations

import base64
import copy
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable

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

SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "all", "base64", "base64offset", "utf16le", "utf16be", "utf16",
    "wide", "windash", "cidr", "exists", "cased", "gt", "gte", "lt", "lte", "fieldref", "i", "m", "s",
}
# Modifiers Sigma defines that the native evaluator doesn't implement.
KNOWN_UNSUPPORTED = {"expand", "minute", "hour", "day", "week", "month", "year"}

PLATFORMS = {"windows", "linux", "macos"}
_WINDASH = ("-", "/", "–", "—", "―")
_WILD = set("*?\\")
_TIME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "M": 2592000, "y": 31536000}
_PLACEHOLDER = re.compile(r"%([A-Za-z0-9_.-]+)%")


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


@lru_cache(maxsize=16384)
def _regex(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _encode(value: str, mods: list[str]) -> bytes:
    if "utf16le" in mods or "wide" in mods:
        return value.encode("utf-16-le")
    if "utf16be" in mods:
        return value.encode("utf-16-be")
    if "utf16" in mods:
        return value.encode("utf-16")       # with BOM, as the spec says
    return value.encode("utf-8")


def _base64offset(raw: bytes) -> list[str]:
    """The three base64 encodings a value can have depending on its offset inside the encoded blob."""
    start, end = (0, 2, 3), (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(b" " * i + raw).decode()
        out.append(enc[start[i]:end[(len(raw) + i) % 3]])
    return out


def _field_value(event: Event, field: str) -> Any:
    if field in event.fields:
        return event.fields[field]
    # case-insensitive fallback, then schema path
    low = field.lower()
    for k, v in event.fields.items():
        if k.lower() == low:
            return v
    return event.get(field)


def _to_number(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _match_one(actual: Any, expected: Any, mods: list[str]) -> bool:
    if "exists" in mods:
        return (actual is not None) == (str(expected).lower() == "true")
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a = str(actual)
    e = str(expected)

    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        x, y = _to_number(actual), _to_number(expected)
        if x is None or y is None:
            return False
        return {"gt": x > y, "gte": x >= y, "lt": x < y, "lte": x <= y}[next(m for m in ("gt", "gte", "lt", "lte") if m in mods)]
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        return _regex(e, flags).search(a) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(a.strip()) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    if "base64offset" in mods:
        rest = [m for m in mods if m not in ("base64offset", "utf16le", "utf16be", "utf16", "wide")]
        return any(_match_one(a, v, rest) for v in _base64offset(_encode(e, mods)))
    if "base64" in mods:
        rest = [m for m in mods if m not in ("base64", "utf16le", "utf16be", "utf16", "wide")]
        return _match_one(a, base64.b64encode(_encode(e, mods)).decode(), rest)
    if "windash" in mods:
        variants = [e]
        for ch in _WINDASH:
            variants += [v.replace("-", ch) for v in variants if "-" in v]
        return any(_match_one(a, v, [m for m in mods if m != "windash"]) for v in dict.fromkeys(variants))

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
            if "fieldref" in mods:                               # compare with another field of the same event
                values = [_field_value(event, str(v)) for v in values]
                if actual is None or any(v is None for v in values):
                    return False                                 # a missing field never matches, on either side
                mods = [m for m in mods if m != "fieldref"]
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
    """The rule can't be represented in Chain yet."""


@dataclass
class SigmaImport:
    rule: dict[str, Any]
    notes: list[str] = field(default_factory=list)   # fidelity notes; empty = exact
    meta: dict[str, Any] = field(default_factory=dict)  # upstream metadata worth keeping


def parse_timespan(value: Any) -> float:
    """Sigma timeframe / timespan (`30s`, `5m`, `24h`, `7d`) -> seconds."""
    s = str(value).strip()
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhdwMy])", s)
    if not m:
        raise SigmaUnsupported(f"bad timeframe {value!r}")
    return float(m.group(1)) * _TIME_UNITS[m.group(2)]


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


def _expand_placeholders(detection: dict[str, Any], placeholders: dict[str, list[str]] | None,
                         notes: list[str]) -> dict[str, Any]:
    """Resolve `|expand` placeholders (`%name%`) from a map; unresolved ones become wildcards."""
    det = copy.deepcopy(detection)
    unresolved: set[str] = set()

    def expand_value(v: Any) -> list[Any]:
        if not isinstance(v, str) or not _PLACEHOLDER.search(v):
            return [v]
        out = [v]
        for name in _PLACEHOLDER.findall(v):
            if placeholders and name in placeholders:
                out = [o.replace(f"%{name}%", str(p)) for o in out for p in placeholders[name]]
            else:
                unresolved.add(name)
                out = [o.replace(f"%{name}%", "*") for o in out]
        return out

    for name, sel in det.items():
        if name in ("condition", "timeframe"):
            continue
        for item in (sel if isinstance(sel, list) else [sel]):
            if not isinstance(item, dict):
                continue
            for key in list(item):
                if "|expand" not in key:
                    continue
                values = item.pop(key)
                values = values if isinstance(values, list) else [values]
                expanded = [x for v in values for x in expand_value(v)]
                new_key = "|".join(p for p in key.split("|") if p != "expand")
                item[new_key] = expanded if len(expanded) != 1 else expanded[0]
    for name in sorted(unresolved):
        notes.append(f"placeholder %{name}% unresolved; treated as a wildcard")
    return det


def _walk_detection(detection: dict[str, Any], notes: list[str]) -> None:
    """Record every feature the native evaluator approximates or ignores; reject what it can't run."""
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
                if "re" in mods:
                    for v in (expected if isinstance(expected, list) else [expected]):
                        try:
                            re.compile(str(v))
                        except re.error as e:
                            raise SigmaUnsupported(f"invalid regex in {key}: {e}") from e
    if detection.get("timeframe") is not None and "|" not in str(detection.get("condition", "")):
        notes.append("timeframe without aggregation ignored")


_AGG_RE = re.compile(
    r"^(?P<cond>.*?)\s*\|\s*(?P<func>count|sum|min|max|avg|near)\s*(?:\((?P<field>[^)]*)\))?"
    r"\s*(?:by\s+(?P<by>[^\s<>=!]+))?\s*(?:(?P<op>>=|<=|==|>|<|!=)\s*(?P<n>\d+(?:\.\d+)?))?\s*$", re.S)


def _aggregation(detection: dict[str, Any], notes: list[str]) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    """Split `cond | count(F) by G > N` into (detection without aggregation, count spec, group_by)."""
    cond = str(detection.get("condition", ""))
    if "|" not in cond:
        return detection, None, None
    m = _AGG_RE.match(cond)
    if not m:
        raise SigmaUnsupported(f"aggregation {cond.split('|', 1)[1].strip()!r} not understood")
    func, op, n = m.group("func"), m.group("op"), m.group("n")
    if func != "count":
        raise SigmaUnsupported(f"aggregation {func}() (only count is supported)")
    if op in (None, "<", "<=", "==", "!="):
        raise SigmaUnsupported(f"aggregation count {op or ''} {n or ''}: only > and >= thresholds convert to a count step")
    threshold = float(n)
    minimum = int(threshold) + 1 if op == ">" else int(-(-threshold // 1))
    if minimum < 2:
        raise SigmaUnsupported("aggregation threshold below 2 is a plain match, not a count")
    tf = detection.get("timeframe")
    if tf is None:
        within, note = 86400.0, "aggregation without timeframe: counting within 24h"
    else:
        within, note = parse_timespan(tf), None
    if note:
        notes.append(note)
    count = {"min": minimum, "within": within}
    fld = (m.group("field") or "").strip()
    if fld:
        count["distinct"] = f"fields.{fld}"
    det = dict(detection)
    det["condition"] = m.group("cond").strip()
    det.pop("timeframe", None)
    by = m.group("by")
    return det, count, f"fields.{by}" if by else None


def _rule_shell(sigma: dict[str, Any], tags_extra: list[str]) -> dict[str, Any]:
    level = sigma.get("level", "medium")
    return {
        "id": "sigma_" + re.sub(r"[^a-z0-9]+", "_", str(sigma.get("id") or sigma.get("title", "rule")).lower()).strip("_"),
        "title": sigma.get("title", ""),
        "description": str(sigma.get("description", "") or ""),
        "severity": {"informational": "info", "critical": "critical"}.get(level, level),
        "action": "alert",
        "tags": list(sigma.get("tags", []) or []) + tags_extra,
    }


def _meta(sigma: dict[str, Any], logsource: dict[str, Any]) -> dict[str, Any]:
    return {
        "upstream_id": str(sigma.get("id", "")),
        "name": sigma.get("name"),
        "status": sigma.get("status"),
        "logsource": dict(logsource),
        "falsepositives": list(sigma.get("falsepositives", []) or []),
        "references": list(sigma.get("references", []) or []),
        "author": sigma.get("author"),
        "date": str(sigma.get("date", "") or ""),
        "modified": str(sigma.get("modified", "") or ""),
    }


def sigma_import(sigma: dict[str, Any] | str, placeholders: dict[str, list[str]] | None = None) -> SigmaImport:
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

    notes: list[str] = []
    detection = _expand_placeholders(sigma["detection"], placeholders, notes)
    detection, count, group_by = _aggregation(detection, notes)
    _walk_detection(detection, notes)
    logsource = sigma.get("logsource") or {}
    event_type = _event_type(logsource, notes)

    step: dict[str, Any] = {"name": "match", "where": {"sigma": {"detection": detection}}}
    if event_type:
        step["event"] = event_type
    product = str(logsource.get("product") or "").lower()
    if product in PLATFORMS:
        # Only applies when the event says where it happened; log pipelines without a platform field are unaffected.
        step["where"]["fields.platform"] = {"when_set": product}
    if count:
        step["count"] = count
    rule = _rule_shell(sigma, ["imported:sigma"])
    rule["sequence"] = [step]
    if group_by:
        rule["group_by"] = group_by
    elif count:
        rule["group_by"] = None   # a global count
    return SigmaImport(rule, notes, _meta(sigma, logsource))


def _threshold(condition: dict[str, Any] | None) -> int:
    if not condition:
        raise SigmaUnsupported("correlation without a condition")
    if "gte" in condition:
        n = int(condition["gte"])
    elif "gt" in condition:
        n = int(condition["gt"]) + 1
    elif "eq" in condition and int(condition["eq"]) >= 2:
        n = int(condition["eq"])
        raise SigmaUnsupported("correlation condition eq (exact counts need a windowed absence)")
    else:
        raise SigmaUnsupported(f"correlation condition {condition} (only gt / gte convert)")
    if n < 2:
        raise SigmaUnsupported("correlation threshold below 2 is a plain match")
    return n


def sigma_import_correlation(sigma: dict[str, Any], resolve: Callable[[str], dict[str, Any] | None]) -> SigmaImport:
    """Convert a Sigma correlation rule into a Chain sequence.

    `resolve(name_or_id)` returns the already-converted Chain rule dict for a referenced Sigma rule.
    """
    corr = sigma["correlation"]
    ctype = corr.get("type")
    refs = corr.get("rules") or []
    if isinstance(refs, str):
        refs = [refs]
    if not refs:
        raise SigmaUnsupported("correlation references no rules")
    steps_src = []
    for ref in refs:
        base = resolve(str(ref))
        if base is None:
            raise SigmaUnsupported(f"correlation references unknown rule {ref!r}")
        steps_src.append((str(ref), base))

    notes: list[str] = []
    timespan = parse_timespan(corr.get("timespan", "1h"))
    if "timespan" not in corr:
        notes.append("correlation without timespan: using 1h")
    group = corr.get("group-by") or corr.get("group_by") or []
    group = [group] if isinstance(group, str) else list(group)
    group_by: Any = [f"fields.{g}" for g in group] if group else None

    def base_step(name: str, base: dict[str, Any]) -> dict[str, Any]:
        st = copy.deepcopy(base["sequence"][0])
        if len(base["sequence"]) != 1 or st.get("count"):
            raise SigmaUnsupported(f"correlation over a rule that is itself a sequence or count ({name})")
        st["name"] = re.sub(r"[^a-z0-9_]+", "_", name.lower()).strip("_") or "step"
        return st

    if ctype in ("event_count", "value_count"):
        if len(steps_src) != 1:
            raise SigmaUnsupported(f"{ctype} over several rules (Chain counts one step)")
        name, base = steps_src[0]
        step = base_step(name, base)
        count: dict[str, Any] = {"min": _threshold(corr.get("condition")), "within": timespan}
        if ctype == "value_count":
            fld = corr.get("field")
            if not fld:
                raise SigmaUnsupported("value_count without a field")
            count["distinct"] = f"fields.{fld}"
        step["count"] = count
        steps = [step]
    elif ctype in ("temporal", "temporal_ordered"):
        if len(steps_src) < 2:
            raise SigmaUnsupported(f"{ctype} needs at least two rules")
        steps = []
        seen: set[str] = set()
        for name, base in steps_src:
            st = base_step(name, base)
            while st["name"] in seen:
                st["name"] += "_"
            seen.add(st["name"])
            steps.append(st)
        if ctype == "temporal":
            notes.append("temporal (unordered) correlation evaluated as an ordered sequence")
    else:
        raise SigmaUnsupported(f"correlation type {ctype!r}")

    rule = _rule_shell(sigma, ["imported:sigma", "sigma:correlation"])
    rule["sequence"] = steps
    rule["window"] = {"seconds": timespan}
    rule["group_by"] = group_by
    meta = _meta(sigma, {})
    meta["correlation"] = {"type": ctype, "rules": [r for r, _ in steps_src]}
    return SigmaImport(rule, notes, meta)


def sigma_to_chain(sigma: dict[str, Any] | str) -> dict[str, Any]:
    """Convert a Sigma rule (dict or YAML string) into a Chain rule dict."""
    return sigma_import(sigma).rule
