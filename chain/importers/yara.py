"""YARA import: every rule becomes a Chain rule evaluated natively by chain.yara.

Rules the native evaluator can't compile (module calls such as pe.* / math.*,
`entrypoint`, wide regexes, oversized xor expansions) are **delegated**: the
rule is kept with its original source (plus the rules it references and the
imports it needs) so a yara-python sensor can run it, and the Chain side
matches on the sensor's output (`fields.yara_matches`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..yara import YaraDetection, YaraSyntax, YaraUnsupported, YRule, compile_detection, parse_file

DELEGATED_EVENTS = ["file.scan", "file.create", "email.attachment"]


class UnsupportedYara(ValueError):
    pass


@dataclass
class YaraImport:
    name: str
    rule: dict[str, Any]
    source: str                       # this rule's own text (plus imports and referenced rules)
    delegated: bool = False
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def _shell(r: YRule, title_suffix: str = "") -> dict[str, Any]:
    level = str(r.meta.get("score", r.meta.get("level", ""))).lower()
    severity = "critical" if level.isdigit() and int(level) >= 80 else "high"
    return {
        "id": f"yara_{r.name}",   # case kept: signature-base has names that differ only by case
        "title": f"YARA {r.name}{title_suffix}",
        "description": str(r.meta.get("description", "")),
        "severity": severity,
        "action": "alert",
        "tags": ["imported:yara"] + [f"yara:{t}" for t in r.tags],
    }


def _native_rule(r: YRule, det: YaraDetection) -> dict[str, Any]:
    spec: dict[str, Any] = {"name": r.name, "strings": [s.to_dict() for s in r.strings], "condition": r.condition}
    deps = det.dependency_specs()
    if deps:
        spec["dependencies"] = deps
    rule = _shell(r)
    rule["sequence"] = [{"name": "match", "event": DELEGATED_EVENTS, "where": {"yara": spec}}]
    return rule


def _delegated_rule(r: YRule) -> dict[str, Any]:
    rule = _shell(r, " (native engine)")
    rule["tags"].append("delegated:yara")
    rule["sequence"] = [{"name": "match", "event": DELEGATED_EVENTS, "where": {"fields.yara_matches": r.name}}]
    return rule


@dataclass
class YaraContext:
    """Every rule of a source, by name, so cross-file references resolve. Build once per source."""
    rules: dict[str, YRule] = field(default_factory=dict)
    specs: dict[str, dict[str, Any]] = field(default_factory=dict)

    def add(self, r: YRule) -> None:
        if r.name not in self.rules:
            self.rules[r.name] = r
            self.specs[r.name] = {"strings": [s.to_dict() for s in r.strings], "condition": r.condition}


def yara_import(source: str, context: YaraContext | None = None) -> list[YaraImport]:
    """Convert every rule in a YARA file. `context` holds the other files of the same source
    that this file may reference (shared, so dependencies compile once)."""
    rules, imports = parse_file(source)
    ctx = context or YaraContext()
    for r in rules:
        ctx.add(r)
    specs, by_name = ctx.specs, ctx.rules
    header = "\n".join(f'import "{m}"' for m in imports)
    out = []
    for r in rules:
        meta = {"meta": dict(r.meta), "private": r.private, "tags": list(r.tags)}
        try:
            det = compile_detection({"name": r.name, "strings": specs[r.name]["strings"], "condition": r.condition,
                                     "dependencies": specs})
        except (YaraUnsupported, YaraSyntax) as e:
            needed = _dependency_sources(r, by_name)
            text = "\n\n".join(x for x in [header, *needed, r.source] if x)
            kind = "unsupported" if isinstance(e, YaraUnsupported) else "not parsed"
            out.append(YaraImport(r.name, _delegated_rule(r), text, delegated=True,
                                  notes=[f"{kind}: {e}: run with yara-python, Chain matches fields.yara_matches"], meta=meta))
            continue
        out.append(YaraImport(r.name, _native_rule(r, det), r.source, meta=meta))
    return out


def _dependency_sources(r: YRule, by_name: dict[str, YRule]) -> list[str]:
    """Source text of the rules `r` references by name (best effort, for the delegated bundle)."""
    import re as _re
    names = set(_re.findall(r"\b([A-Za-z_]\w*)\b", r.condition))
    out, seen = [], {r.name}
    todo = [n for n in names if n in by_name and n != r.name]
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        dep = by_name[n]
        out.insert(0, dep.source)
        todo += [m for m in set(_re.findall(r"\b([A-Za-z_]\w*)\b", dep.condition)) if m in by_name and m not in seen]
    return out


def yara_to_chain(source: str) -> list[dict[str, Any]]:
    """Chain rules for every rule in a YARA file (delegated ones included)."""
    return [imp.rule for imp in yara_import(source)]
