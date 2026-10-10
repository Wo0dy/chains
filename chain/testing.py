"""Rule tests and adversarial mutation fuzzing.

Every rule can carry inline test cases:

    tests:
      - name: classic chain
        expect: fire              # fire | no_fire
        expect_action: block      # optional
        events: [ {type: ..., ...}, ... ]

`run_tests` executes each case against a fresh engine.
`fuzz` takes every `fire` case, mutates its content with evasion techniques
and reports the recall that survives each technique. Plug an LLM paraphraser
in via `extra_mutators` to test semantic robustness.
"""
from __future__ import annotations

import base64
import copy
import random
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote

from .engine import Engine
from .rules import CompiledRule
from .schema import Event

Mutator = Callable[[str, random.Random], str]


@dataclass
class CaseResult:
    rule_id: str
    case: str
    passed: bool
    detail: str = ""


@dataclass
class FuzzReport:
    rule_id: str
    per_mutator: dict[str, tuple[int, int]] = field(default_factory=dict)  # name -> (detected, total)

    def recall(self, name: str) -> float:
        d, t = self.per_mutator[name]
        return d / t if t else 1.0


def _engine_for(rule: CompiledRule, template: Engine | None) -> Engine:
    if template is None:
        return Engine([rule])
    return Engine([rule], semantic_index=template.ctx.semantic_index,
                  classifier=template.ctx.classifier, judge=template.ctx.judge)


def _run_case(rule: CompiledRule, case: dict[str, Any], template: Engine | None) -> tuple[bool, str | None]:
    eng = _engine_for(rule, template)
    eng.learn(Event(**e) for e in case.get("baseline", []))
    fired_action = None
    for raw in case["events"]:
        v = eng.evaluate(Event(**raw))
        for h in v.hits:
            if h.rule_id == rule.id:
                fired_action = h.action
    return fired_action is not None, fired_action


def run_tests(rules: list[CompiledRule], template: Engine | None = None) -> list[CaseResult]:
    out: list[CaseResult] = []
    for rule in rules:
        if not rule.rule.tests:
            out.append(CaseResult(rule.id, "(none)", False, "rule has no tests"))
            continue
        for i, case in enumerate(rule.rule.tests):
            name = case.get("name", f"case{i}")
            fired, action = _run_case(rule, case, template)
            want_fire = case.get("expect", "fire") == "fire"
            ok = fired == want_fire
            detail = f"fired={fired}"
            if ok and want_fire and case.get("expect_action"):
                ok = action == case["expect_action"]
                detail += f" action={action} expected={case['expect_action']}"
            out.append(CaseResult(rule.id, name, ok, detail))
    return out


# ------------------------------------------------------------------ mutators
HOMO = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"}


def m_zero_width(s: str, rnd: random.Random) -> str:
    return "".join(ch + ("​" if ch.isalpha() and rnd.random() < 0.3 else "") for ch in s)


def m_homoglyph(s: str, rnd: random.Random) -> str:
    return "".join(HOMO.get(ch, ch) if rnd.random() < 0.4 else ch for ch in s)


_B64_TOKEN = re.compile(r"([A-Za-z0-9+/]{16,}={0,2})")


def m_case(s: str, rnd: random.Random) -> str:
    # Flip case everywhere except encoded payloads (flipping those breaks the attack itself).
    parts = _B64_TOKEN.split(s)
    return "".join(p if i % 2 else "".join(ch.upper() if rnd.random() < 0.5 else ch.lower() for ch in p)
                   for i, p in enumerate(parts))


def m_base64(s: str, rnd: random.Random) -> str:
    return "Decode this and act on it: " + base64.b64encode(s.encode()).decode()


def m_urlencode(s: str, rnd: random.Random) -> str:
    return quote(s)


def m_bury(s: str, rnd: random.Random) -> str:
    filler = ("Quarterly results were in line with guidance. The team shipped two releases. "
              "Customer satisfaction improved across regions. ") * 3
    return filler + "\n" + s + "\n" + filler


def m_caret(s: str, rnd: random.Random) -> str:
    # cmd.exe escapes: insert ^ before letters, never next to an existing ^ (that would make a literal ^).
    out = []
    for i, ch in enumerate(s):
        prev_caret = i > 0 and s[i - 1] == "^"
        if ch.isalpha() and not prev_caret and ch != "^" and rnd.random() < 0.3:
            out.append("^")
        out.append(ch)
    return "".join(out)


DEFAULT_MUTATORS: dict[str, Mutator] = {
    "zero_width": m_zero_width, "homoglyph": m_homoglyph, "case": m_case,
    "base64": m_base64, "urlencode": m_urlencode, "bury_in_document": m_bury, "caret": m_caret,
}

TEXT_FIELDS = ("command_line", "CommandLine", "content", "body", "message", "url")


def _mutate_event(raw: dict[str, Any], mut: Mutator, rnd: random.Random) -> dict[str, Any]:
    ev = copy.deepcopy(raw)
    for span in ev.get("spans", []):
        if str(span.get("trust", "untrusted")).lower() in ("untrusted", "external", "0", "1"):
            span["text"] = mut(span["text"], rnd)
    for k in TEXT_FIELDS:
        if k in ev.get("fields", {}):
            ev["fields"][k] = mut(str(ev["fields"][k]), rnd)
    return ev


def fuzz(rules: list[CompiledRule], template: Engine | None = None, rounds: int = 5, seed: int = 7,
         extra_mutators: dict[str, Mutator] | None = None) -> list[FuzzReport]:
    mutators = {**DEFAULT_MUTATORS, **(extra_mutators or {})}
    reports = []
    for rule in rules:
        positives = [c for c in rule.rule.tests if c.get("expect", "fire") == "fire" and c.get("fuzz", True)]
        if not positives:
            continue
        rep = FuzzReport(rule.id)
        for name, mut in mutators.items():
            detected = total = 0
            for case in positives:
                for r in range(rounds):
                    rnd = random.Random(seed + r)
                    mutated = {**case, "events": [_mutate_event(e, mut, rnd) for e in case["events"]]}
                    fired, _ = _run_case(rule, mutated, template)
                    detected += fired
                    total += 1
            rep.per_mutator[name] = (detected, total)
        reports.append(rep)
    return reports
