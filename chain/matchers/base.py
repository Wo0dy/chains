from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# Tier costs drive cascade order: cheapest matchers run first and
# expensive ones are skipped once the outcome is decided.
TIER_COST = {"deterministic": 1, "semantic": 10, "classifier": 20, "judge": 1000}


@dataclass
class MatchResult:
    hit: bool
    score: float = 0.0
    tier: str = "deterministic"
    matcher: str = ""
    detail: str = ""
    uncertain: bool = False          # in a gray zone: eligible for judge escalation
    extra: dict[str, Any] = field(default_factory=dict)


class Matcher(Protocol):
    tier: str
    name: str

    def match(self, text: str, ctx: "MatchContext") -> MatchResult: ...


@dataclass
class MatchContext:
    """Shared services matchers can use."""

    semantic_index: Any = None
    classifier: Any = None
    judge: Any = None
    rule_id: str = ""
