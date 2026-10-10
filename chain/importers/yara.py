"""Basic YARA import: text and regex strings with `any/all/N of them` conditions.

Hex strings, modules (pe, elf, math) and complex conditions can't run in
Chain's text matchers. `yara_import` reports those as `delegated`: the rule
is kept with its original source so a yara-python sensor can run it, and the
Chain side matches on the sensor's output (`fields.yara_matches`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

RULE_RE = re.compile(r"(?:^|\n)\s*(?:(?:private|global)\s+)*rule\s+(\w+)[^{]*\{(.*?)\n\}", re.S)
STR_RE = re.compile(r'\$(\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|/((?:[^/\\]|\\.)*)/([is]*))([^\n]*)')
COND_RE = re.compile(r"condition:\s*(.+?)\s*$", re.S)
IMPORT_RE = re.compile(r'^\s*import\s+"(\w+)"', re.M)

DELEGATED_EVENTS = ["file.scan", "file.create", "email.attachment"]


class UnsupportedYara(ValueError):
    pass


@dataclass
class YaraImport:
    name: str
    rule: dict[str, Any]
    source: str                       # this rule's own text (plus imports it needs)
    delegated: bool = False
    notes: list[str] = field(default_factory=list)


def split_rules(source: str) -> list[tuple[str, str, str]]:
    """Return (name, body, full_text) for each rule in a YARA file."""
    out = []
    for m in RULE_RE.finditer(source):
        out.append((m.group(1), m.group(2), m.group(0).strip()))
    return out


def _convert(name: str, body: str) -> dict[str, Any]:
    if re.search(r"\$\w*\s*=\s*\{", body):
        raise UnsupportedYara("hex strings")
    strings, regexes = [], []
    for _id, text, rx, rx_flags, mods in STR_RE.findall(body):
        if text:
            strings.append(bytes(text, "utf-8").decode("unicode_escape"))
        elif rx:
            regexes.append((rx, "i" if "i" in rx_flags or "nocase" in mods else ""))
    cond_m = COND_RE.search(body)
    cond = cond_m.group(1).strip() if cond_m else "any of them"
    total = len(strings) + len(regexes)
    if total == 0:
        raise UnsupportedYara("no text or regex strings")
    if cond == "any of them":
        need = 1
    elif cond == "all of them":
        need = total
    elif m := re.fullmatch(r"(\d+) of them", cond):
        need = int(m.group(1))
    else:
        raise UnsupportedYara(f"condition {cond!r}")

    matchers: list[dict[str, Any]] = [{"strings": [t]} for t in strings]
    matchers += [{"regex": rx, "flags": fl} for rx, fl in regexes]
    return {
        "id": f"yara_{name.lower()}",
        "title": f"YARA {name}",
        "severity": "high",
        "action": "alert",
        "tags": ["imported:yara"],
        "sequence": [{"name": "match", "event": DELEGATED_EVENTS, "match": {"any": matchers, "min": need}}],
    }


def _delegated(name: str) -> dict[str, Any]:
    return {
        "id": f"yara_{name.lower()}",
        "title": f"YARA {name} (native engine)",
        "severity": "high",
        "action": "alert",
        "tags": ["imported:yara", "delegated:yara"],
        "sequence": [{"name": "match", "event": DELEGATED_EVENTS, "where": {"fields.yara_matches": name}}],
    }


def yara_import(source: str) -> list[YaraImport]:
    """Convert every rule in a YARA file; rules Chain can't run are delegated, not dropped."""
    imports = "\n".join(f'import "{m}"' for m in IMPORT_RE.findall(source))
    out = []
    for name, body, text in split_rules(source):
        full = f"{imports}\n\n{text}".strip() if imports else text
        try:
            out.append(YaraImport(name, _convert(name, body), full))
        except UnsupportedYara as e:
            out.append(YaraImport(name, _delegated(name), full, delegated=True,
                                  notes=[f"{e}: run with yara-python, Chain matches fields.yara_matches"]))
    return out


def yara_to_chain(source: str) -> list[dict[str, Any]]:
    """Chain rules for the convertible rules in a YARA file. Raises on the first one that isn't."""
    rules = []
    for imp in yara_import(source):
        if imp.delegated:
            raise UnsupportedYara(f"{imp.name}: {imp.notes[0]}")
        rules.append(imp.rule)
    return rules
