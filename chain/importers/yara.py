"""Basic YARA import: text and regex strings with `any/all/N of them` conditions.

Hex strings, modules (pe, elf, math) and complex conditions are reported as
unsupported so you know which rules still need the native YARA engine.
For full fidelity, call yara-python from a `file.scan` sensor and feed its
match names into Chain as event fields (`fields.yara_matches`).
"""
from __future__ import annotations

import re
from typing import Any

RULE_RE = re.compile(r"rule\s+(\w+)[^{]*\{(.*?)\n\}", re.S)
STR_RE = re.compile(r'\$(\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|/((?:[^/\\]|\\.)*)/([is]*))([^\n]*)')
COND_RE = re.compile(r"condition:\s*(.+?)\s*$", re.S)


class UnsupportedYara(ValueError):
    pass


def yara_to_chain(source: str) -> list[dict[str, Any]]:
    rules = []
    for name, body in RULE_RE.findall(source):
        if re.search(r"\$\w*\s*=\s*\{", body):
            raise UnsupportedYara(f"{name}: hex strings not supported by importer")
        strings, regexes = [], []
        for _id, text, rx, rx_flags, mods in STR_RE.findall(body):
            if text:
                strings.append(bytes(text, "utf-8").decode("unicode_escape"))
            elif rx:
                regexes.append((rx, "i" if "i" in rx_flags or "nocase" in mods else ""))
        cond_m = COND_RE.search(body)
        cond = cond_m.group(1).strip() if cond_m else "any of them"
        total = len(strings) + len(regexes)
        if cond == "any of them":
            need = 1
        elif cond == "all of them":
            need = total
        elif m := re.fullmatch(r"(\d+) of them", cond):
            need = int(m.group(1))
        else:
            raise UnsupportedYara(f"{name}: condition {cond!r} not supported by importer")

        matchers: list[dict[str, Any]] = [{"strings": [t]} for t in strings]
        matchers += [{"regex": rx, "flags": fl} for rx, fl in regexes]
        match = {"any": matchers, "min": need}
        rules.append({
            "id": f"yara_{name.lower()}",
            "title": f"YARA {name}",
            "severity": "high",
            "action": "alert",
            "tags": ["imported:yara"],
            "sequence": [{"name": "match", "event": ["file.scan", "file.create", "email.attachment"], "match": match}],
        })
    return rules
