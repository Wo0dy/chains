"""Replay labeled history through the engine and score each rule.

Input is JSONL, one event per line. An event that some rule *should* fire on
carries a `labels` list of rule ids:

    {"type": "net.flow", "host": "ws-17", ..., "labels": ["classic_phish_to_ransomware"]}

Label the event a rule fires on: the last step of a sequence, the event that
crosses a count threshold, or, for a rule ending in a "not followed by" step,
the event the absence is measured from.

Scoring, per rule:
    TP  rule fired on a labeled event
    FP  rule fired on an event not labeled for it
    FN  event labeled for the rule, but it didn't fire there
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .engine import Engine
from .schema import Event


@dataclass
class RuleScore:
    rule_id: str
    tp: list[str] = field(default_factory=list)   # event ids
    fp: list[str] = field(default_factory=list)
    fn: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        n = len(self.tp) + len(self.fp)
        return len(self.tp) / n if n else None

    @property
    def recall(self) -> float | None:
        n = len(self.tp) + len(self.fn)
        return len(self.tp) / n if n else None

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "tp": len(self.tp), "fp": len(self.fp), "fn": len(self.fn),
                "precision": self.precision, "recall": self.recall,
                "fp_events": self.fp, "fn_events": self.fn}


@dataclass
class ReplayReport:
    rules: list[RuleScore]
    events: int = 0
    unknown_labels: list[str] = field(default_factory=list)   # labels naming no loaded rule

    @property
    def total(self) -> RuleScore:
        t = RuleScore("(all rules)")
        for r in self.rules:
            t.tp += r.tp
            t.fp += r.fp
            t.fn += r.fn
        return t

    def failures(self, min_precision: float = 0.0, min_recall: float = 0.0) -> list[str]:
        """Rules below either threshold. Rules with no hits and no labels are skipped."""
        out = []
        for r in self.rules:
            if r.precision is not None and r.precision < min_precision:
                out.append(f"{r.rule_id}: precision {r.precision:.2f} < {min_precision}")
            if r.recall is not None and r.recall < min_recall:
                out.append(f"{r.rule_id}: recall {r.recall:.2f} < {min_recall}")
        return out

    def to_dict(self) -> dict[str, Any]:
        return {"events": self.events, "total": self.total.to_dict(),
                "rules": [r.to_dict() for r in self.rules], "unknown_labels": self.unknown_labels}

    def table(self, verbose: bool = False) -> str:
        def pct(v: float | None) -> str:
            return "   n/a" if v is None else f"{v:6.0%}"

        lines = [f"{'rule':42s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'prec':>6s} {'recall':>6s}"]
        for r in self.rules + [self.total]:
            lines.append(f"{r.rule_id:42s} {len(r.tp):4d} {len(r.fp):4d} {len(r.fn):4d} "
                         f"{pct(r.precision)} {pct(r.recall)}")
            if verbose and r.rule_id != "(all rules)":
                lines += [f"    FP {e}" for e in r.fp] + [f"    FN {e}" for e in r.fn]
        lines.append(f"\n{self.events} events replayed")
        if self.unknown_labels:
            lines.append(f"labels for unknown rules: {', '.join(sorted(set(self.unknown_labels)))}")
        return "\n".join(lines)


def _labels(raw: dict[str, Any]) -> list[str]:
    v = raw.pop("labels", [])
    return [v] if isinstance(v, str) else list(v)


def replay(engine: Engine, records: Iterable[dict[str, Any]]) -> ReplayReport:
    """Run labeled event dicts through `engine` (in order) and score every rule."""
    expected: set[tuple[str, str]] = set()
    fired: set[tuple[str, str]] = set()
    known = {r.id for r in engine.rules}
    report = ReplayReport([])
    last_ts = None

    for raw in records:
        raw = dict(raw)
        labels = _labels(raw)
        ev = Event(**raw)
        report.events += 1
        for rule_id in labels:
            if rule_id in known:
                expected.add((rule_id, ev.id))
            else:
                report.unknown_labels.append(rule_id)
        for v in engine.advance_time(ev.ts) + [engine.evaluate(ev)]:
            fired |= {(h.rule_id, v.event_id) for h in v.hits}
        last_ts = ev.ts

    if last_ts is not None:
        for v in engine.advance_time(last_ts):
            fired |= {(h.rule_id, v.event_id) for h in v.hits}

    for rule in engine.rules:
        score = RuleScore(rule.id)
        exp = {e for r, e in expected if r == rule.id}
        got = {e for r, e in fired if r == rule.id}
        score.tp, score.fp, score.fn = sorted(exp & got), sorted(got - exp), sorted(exp - got)
        report.rules.append(score)
    return report


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]
