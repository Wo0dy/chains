"""Matcher factory + cascade evaluation (cheapest tier first, short-circuit)."""
from __future__ import annotations

from typing import Any

from .base import TIER_COST, MatchContext, MatchResult
from .deterministic import RegexMatcher, StringsMatcher
from .models import ClassifierMatcher, Judge, JudgeMatcher, KeywordClassifier
from .semantic import HashingEmbedder, SemanticIndex, SemanticMatcher

__all__ = [
    "MatchContext", "MatchResult", "build_matcher", "MatchExpr", "SemanticIndex",
    "HashingEmbedder", "KeywordClassifier", "Judge",
]


def build_matcher(spec: dict[str, Any]):
    if "regex" in spec:
        return RegexMatcher(spec["regex"], spec.get("flags", "i"))
    if "strings" in spec:
        return StringsMatcher(spec["strings"], spec.get("min", 1), spec.get("nocase", True))
    if "semantic" in spec:
        s = spec["semantic"]
        return SemanticMatcher(s["cluster"], s.get("threshold", 0.6), s.get("gray_band", 0.15))
    if "classifier" in spec:
        c = spec["classifier"]
        return ClassifierMatcher(c["label"], c.get("threshold", 0.8), c.get("gray_band", 0.2))
    if "judge" in spec:
        j = spec["judge"]
        return JudgeMatcher(j["question"], j.get("threshold", 0.7))
    raise ValueError(f"unknown matcher spec: {spec}")


class MatchExpr:
    """`any` / `all` tree of matchers, evaluated as a cost-ordered cascade."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.mode = "all" if "all" in spec else "any"
        items = spec.get(self.mode, [])
        self.children: list[Any] = []
        for item in items:
            if "any" in item or "all" in item:
                self.children.append(MatchExpr(item))
            else:
                self.children.append(build_matcher(item))
        self.children.sort(key=self._cost)
        self.min_hits: int = int(spec.get("min", 1))   # `any` + `min: N` = "N of these"
        self.escalate_question: str | None = spec.get("escalate")
        self.raw_text = spec.get("on", "normalized") == "raw"

    @staticmethod
    def _cost(child: Any) -> int:
        if isinstance(child, MatchExpr):
            return max((MatchExpr._cost(c) for c in child.children), default=0)
        return TIER_COST.get(child.tier, 50)

    def evaluate(self, text: str, ctx: MatchContext) -> tuple[bool, list[MatchResult]]:
        results: list[MatchResult] = []
        hits = 0
        for child in self.children:
            if isinstance(child, MatchExpr):
                ok, sub = child.evaluate(text, ctx)
                results.extend(sub)
            else:
                r = child.match(text, ctx)
                results.append(r)
                ok = r.hit
            hits += bool(ok)
            if self.mode == "any" and hits >= self.min_hits:
                return True, results
            if self.mode == "all" and not ok:
                return False, results

        decided = self.mode == "all"
        if not decided and self.escalate_question and any(r.uncertain for r in results):
            jr = JudgeMatcher(self.escalate_question).match(text, ctx)
            results.append(jr)
            return jr.hit, results
        return decided, results
