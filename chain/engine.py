"""The Chain engine: event in, verdict out.

Per event:
  1. provenance/taint is recorded (artifact edges + agent context)
  2. every rule's in-flight sequences for this group are advanced
  3. step checks run cheapest-first: type -> where -> same -> taint -> content matchers
  4. completed sequences become Hits; the strongest action wins the Verdict
  5. baselines learn from the event after evaluation (so it doesn't mask itself)

Absence ("not followed by") at the end of a sequence can only be confirmed by
the clock. Those hits are produced by `advance_time(now)` as separate verdicts,
never folded into the verdict of whatever unrelated event happened to arrive.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .matchers import Judge, KeywordClassifier, MatchContext, SemanticIndex
from .normalize import normalize
from .predicates import BaselineStore, check_where, hashable
from .provenance import ProvenanceTracker, TaintInfo
from .rules import CompiledRule, CompiledStep, load_rules
from .schema import Event
from .verdict import Evidence, Hit, Verdict

MAX_PARTIALS = 256  # per rule per group; oldest dropped first


def _group_key(event: Event, fields: tuple[str, ...]) -> tuple:
    return tuple(event.get(f) for f in fields)


@dataclass
class Partial:
    next_idx: int
    started_ts: float
    started_count: int
    bound: dict[str, Event] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    tiers: set[str] = field(default_factory=set)
    scores: list[float] = field(default_factory=list)
    last_ts: float = 0.0                                   # ts of the most recent bound event
    counted: list[tuple[float, Any]] = field(default_factory=list)  # (ts, key) for a count step


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
        self._by_id = {r.id: r for r in self.rules}
        # Event-type index: a rule only needs to see events whose type one of its steps accepts.
        # Rules with glob patterns are checked for every event; exact types are looked up.
        self._order = {id(r): i for i, r in enumerate(self.rules)}
        self._exact: dict[str, list[CompiledRule]] = defaultdict(list)
        self._globbed: list[CompiledRule] = []
        for r in self.rules:
            pats = {p for st in r.steps for p in st.spec.event}
            if any(any(ch in p for ch in "*?[") for p in pats):
                self._globbed.append(r)
            else:
                for p in pats:
                    self._exact[p].append(r)
        self._group_fields = sorted({r.group_fields for r in self.rules})
        self._timed = {r.id for r in self.rules if r.steps[-1].spec.absent}
        self._ready: list[Verdict] = []   # absence verdicts resolved but not yet handed out

    # ----------------------------------------------------------------- builders
    @classmethod
    def from_paths(
        cls,
        rules_path: str | Path | Iterable[str | Path],
        clusters_path: str | Path | None = None,
        judge: Judge | None = None,
    ) -> "Engine":
        """Build an engine from one or more rule directories, e.g. ("rules", "corpus/sigmahq")."""
        paths = [rules_path] if isinstance(rules_path, (str, Path)) else list(rules_path)
        rules = [r for p in paths for r in load_rules(p)]
        index = SemanticIndex().load_dir(clusters_path) if clusters_path and Path(clusters_path).exists() else None
        return cls(rules, semantic_index=index, classifier=KeywordClassifier(), judge=judge)

    def learn(self, events: Iterable[Event]) -> None:
        """Seed baselines from known-good history (no detection, no taint)."""
        for e in events:
            self.baseline.observe(e, self._rare_keys)

    # --------------------------------------------------------------- evaluate
    def evaluate(self, event: Event) -> Verdict:
        # Resolve absences that came due before this event, so a window expiry
        # below can't silently drop them. They're handed out by advance_time.
        self._resolve_absences(event.ts)
        taint = self.provenance.record(event)
        verdict = Verdict(event_id=event.id)
        text_cache: dict[bool, str] = {}

        # One event counts once per group, however many rules share that group.
        for gf in self._group_fields:
            self._group_count[(gf, _group_key(event, gf))] += 1

        for rule in self._candidates(event.type):
            group = (rule.group_fields, _group_key(event, rule.group_fields))
            hit = self._advance(rule, event, taint, group, text_cache)
            if hit:
                verdict.hits.append(hit)

        self.baseline.observe(event, self._rare_keys)
        return verdict

    def _candidates(self, event_type: str) -> list[CompiledRule]:
        exact = self._exact.get(event_type)
        if not exact:
            return self._globbed
        if not self._globbed:
            return exact
        return sorted(exact + self._globbed, key=lambda r: self._order[id(r)])

    def evaluate_many(self, events: Iterable[Event]) -> list[Verdict]:
        out: list[Verdict] = []
        for e in events:
            out += self.advance_time(e.ts)
            out.append(self.evaluate(e))
        return out

    def advance_time(self, now: float) -> list[Verdict]:
        """Fire every "not followed by" sequence whose waiting time has passed by `now`."""
        self._resolve_absences(now)
        ready, self._ready = self._ready, []
        return ready

    def _resolve_absences(self, now: float) -> None:
        for key, partials in self._partials.items():
            if key[0] not in self._timed:
                continue
            rule = self._by_id[key[0]]
            last = rule.steps[-1]
            keep = []
            for p in partials:
                if p.next_idx == len(rule.steps) - 1 and now - p.last_ts >= last.spec.within:
                    anchor = list(p.bound.values())[-1]
                    p.evidence = p.evidence + [self._absence_evidence(last, f"within {last.spec.within:g}s")]
                    self._ready.append(Verdict(event_id=anchor.id, hits=[self._make_hit(rule, p)], deferred=True))
                else:
                    keep.append(p)
            self._partials[key] = keep

    # ---------------------------------------------------------------- internals
    def _advance(self, rule: CompiledRule, event: Event, taint: TaintInfo, group, text_cache) -> Hit | None:
        key = (rule.id, group)
        partials = self._expire(rule, self._partials[key], event, group)
        new_partials: list[Partial] = []
        dead: set[int] = set()
        completed: Partial | None = None

        candidates = list(partials)
        fresh: Partial | None = None
        # A count step at the start keeps one accumulator per group instead of
        # a fresh partial per event.
        if not (rule.steps[0].spec.count and any(p.next_idx == 0 for p in partials)):
            fresh = Partial(0, event.ts, self._group_count[group], last_ts=event.ts)
            candidates.append(fresh)

        for p in candidates:
            idx = p.next_idx
            step = rule.steps[idx]
            skipped: Evidence | None = None
            if step.spec.absent:
                hit_absent, _, _ = self._check_step(step, event, taint, p, text_cache)
                if hit_absent:
                    dead.add(id(p))          # the forbidden event happened: this chain is off
                    continue
                if idx == len(rule.steps) - 1:
                    continue                 # final absence: the clock decides (advance_time)
                prev = list(p.bound.values())[-1]
                skipped = self._absence_evidence(step, f"between {prev.type} {prev.id} and the next step")
                idx += 1
                step = rule.steps[idx]

            ok, ev, results = self._check_step(step, event, taint, p, text_cache)
            if not ok:
                continue

            started_ts = p.started_ts
            if step.spec.count:
                c = step.spec.count
                k = hashable(event.get(c.distinct)) if c.distinct else event.id
                p.counted = [x for x in p.counted if event.ts - x[0] <= c.within] + [(event.ts, k)]
                n = len({x[1] for x in p.counted})
                if n < c.min:
                    if p is fresh:
                        new_partials.append(p)   # start accumulating
                    continue
                what = f"distinct {c.distinct}" if c.distinct else "events"
                ev.details.append(f"count: {n} {what} >= {c.min} within {c.within:g}s")
                if idx == 0:
                    started_ts = p.counted[0][0]
                p.counted = []                   # reset, so the same burst doesn't fire twice
                if p is fresh:
                    new_partials.append(p)

            adv = Partial(
                idx + 1, started_ts, p.started_count,
                {**p.bound, step.spec.name: event}, p.evidence + ([skipped] if skipped else []) + [ev],
                p.tiers | {r.tier for r in results if r.hit},
                p.scores + [r.score for r in results if r.hit],
                last_ts=event.ts,
            )
            if adv.next_idx == len(rule.steps):
                if completed is None or len(adv.evidence) > len(completed.evidence):
                    completed = adv
            else:
                new_partials.append(adv)

        kept = [p for p in partials if id(p) not in dead]
        self._partials[key] = (kept + new_partials)[-MAX_PARTIALS:]
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
            if p.next_idx == 0:
                out.append(p)   # count accumulator: prunes itself by count.within
                continue
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

    @staticmethod
    def _absence_evidence(step: CompiledStep, when: str) -> Evidence:
        same = f" with same {step.spec.same}" if step.spec.same else ""
        return Evidence(step.spec.name, "", "absent", [f"no {'|'.join(step.spec.event)}{same} {when}"])

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
