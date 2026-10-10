"""The Chain engine: event in, verdict out.

Per event:
  1. provenance/taint is recorded (artifact edges + agent context)
  2. every rule's in-flight sequences for this group are advanced
  3. step checks run cheapest-first: type -> where -> same -> taint -> content matchers
  4. completed sequences become Hits; the strongest action wins the Verdict
  5. baselines learn from the event after evaluation (so it doesn't mask itself)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .matchers import Judge, KeywordClassifier, MatchContext, SemanticIndex
from .normalize import normalize
from .predicates import BaselineStore, check_where
from .provenance import ProvenanceTracker, TaintInfo
from .rules import CompiledRule, CompiledStep, load_rules
from .schema import Event
from .verdict import Evidence, Hit, Verdict

MAX_PARTIALS = 256  # per rule per group; oldest dropped first


@dataclass
class Partial:
    next_idx: int
    started_ts: float
    started_count: int
    bound: dict[str, Event] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    tiers: set[str] = field(default_factory=set)
    scores: list[float] = field(default_factory=list)


class Engine:
    def __init__(
        self,
        rules: Iterable[CompiledRule],
        semantic_index: SemanticIndex | None = None,
        classifier: Any = None,
        judge: Judge | None = None,
        baseline: BaselineStore | None = None,
    ) -> None:
        self.rules = list(rules)
        self.provenance = ProvenanceTracker()
        self.baseline = baseline or BaselineStore()
        self.ctx = MatchContext(semantic_index=semantic_index, classifier=classifier, judge=judge)
        self._partials: dict[tuple[str, Any], list[Partial]] = defaultdict(list)
        self._group_count: dict[tuple[str, Any], int] = defaultdict(int)
        self._rare_keys = sorted({k for r in self.rules for s in r.steps for k in s.rare_keys})

    # ----------------------------------------------------------------- builders
    @classmethod
    def from_paths(
        cls,
        rules_path: str | Path,
        clusters_path: str | Path | None = None,
        judge: Judge | None = None,
    ) -> "Engine":
        index = SemanticIndex().load_dir(clusters_path) if clusters_path and Path(clusters_path).exists() else None
        return cls(load_rules(rules_path), semantic_index=index, classifier=KeywordClassifier(), judge=judge)

    def learn(self, events: Iterable[Event]) -> None:
        """Seed baselines from known-good history (no detection, no taint)."""
        for e in events:
            self.baseline.observe(e, self._rare_keys)

    # --------------------------------------------------------------- evaluate
    def evaluate(self, event: Event) -> Verdict:
        taint = self.provenance.record(event)
        verdict = Verdict(event_id=event.id)
        text_cache: dict[bool, str] = {}

        for rule in self.rules:
            group = (rule.rule.group_by, event.get(rule.rule.group_by))
            self._group_count[group] += 1
            hit = self._advance(rule, event, taint, group, text_cache)
            if hit:
                verdict.hits.append(hit)

        self.baseline.observe(event, self._rare_keys)
        return verdict

    def evaluate_many(self, events: Iterable[Event]) -> list[Verdict]:
        return [self.evaluate(e) for e in events]

    # ---------------------------------------------------------------- internals
    def _advance(self, rule: CompiledRule, event: Event, taint: TaintInfo, group, text_cache) -> Hit | None:
        key = (rule.id, group)
        partials = self._expire(rule, self._partials[key], event, group)
        new_partials: list[Partial] = []
        completed: Partial | None = None

        candidates = partials + [Partial(0, event.ts, self._group_count[group])]
        for p in candidates:
            step = rule.steps[p.next_idx]
            ok, ev, results = self._check_step(step, event, taint, p, text_cache)
            if not ok:
                continue
            adv = Partial(
                p.next_idx + 1, p.started_ts, p.started_count,
                {**p.bound, step.spec.name: event}, p.evidence + [ev],
                p.tiers | {r.tier for r in results if r.hit},
                p.scores + [r.score for r in results if r.hit],
            )
            if adv.next_idx == len(rule.steps):
                if completed is None or len(adv.evidence) > len(completed.evidence):
                    completed = adv
            else:
                new_partials.append(adv)

        self._partials[key] = (partials + new_partials)[-MAX_PARTIALS:]
        if completed is None:
            return None
        # A completed chain consumes the partials it was built from, so the same
        # chain doesn't fire again on every later event.
        started = completed.started_count
        self._partials[key] = [p for p in self._partials[key] if p.started_count != started]
        return self._make_hit(rule, completed)

    def _expire(self, rule: CompiledRule, partials: list[Partial], event: Event, group) -> list[Partial]:
        w = rule.rule.window
        out = []
        for p in partials:
            if w.seconds is not None and event.ts - p.started_ts > w.seconds:
                continue
            if w.steps is not None and self._group_count[group] - p.started_count > w.steps:
                continue
            out.append(p)
        return out

    def _check_step(self, step: CompiledStep, event: Event, taint: TaintInfo, p: Partial, text_cache):
        spec = step.spec
        details: list[str] = []
        if not spec.type_matches(event.type):
            return False, None, []

        ok, where_ev = check_where(event, step.where, self.baseline)
        if not ok:
            return False, None, []
        details += where_ev

        if spec.same and p.bound:
            prev = list(p.bound.values())[-1]
            for f in spec.same:
                if event.get(f) != prev.get(f):
                    return False, None, []
            details.append(f"same {spec.same} as previous step")

        if spec.tainted_by:
            src = p.bound.get(spec.tainted_by)
            if src is None or src.id not in taint.sources:
                return False, None, []
            attr = self.provenance.attribution(event, src.id)
            if attr < spec.min_attribution:
                return False, None, []
            via = taint.via.get(src.id, "?")
            details.append(f"tainted by step {spec.tainted_by} ({src.id}) via {via}; attribution {attr:.2f}")

        results = []
        if step.match is not None:
            raw = step.match.raw_text
            if raw not in text_cache:
                text_cache[raw] = event.text if raw else normalize(event.text)
            self.ctx.rule_id = ""
            hit, results = step.match.evaluate(text_cache[raw], self.ctx)
            if not hit:
                return False, None, []
            details += [f"[{r.tier}] {r.matcher}: {r.detail}" for r in results if r.hit]

        return True, Evidence(spec.name, event.id, event.type, details), results

    def _make_hit(self, rule: CompiledRule, p: Partial) -> Hit:
        r = rule.rule
        conf = r.confidence
        if p.scores:
            conf *= min(1.0, 0.5 + sum(p.scores) / len(p.scores) / 2)
        return Hit(
            rule_id=r.id, title=r.title, severity=r.severity, action=r.action,
            confidence=round(conf, 3), response=list(r.response),
            tiers=sorted(p.tiers), evidence=p.evidence, tags=list(r.tags),
        )
