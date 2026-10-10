"""Tier 1: exact, cheap, auditable. Same power as YARA strings / Sigma modifiers."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .base import MatchContext, MatchResult


@dataclass
class RegexMatcher:
    pattern: str
    flags: str = "i"
    tier: str = "deterministic"
    name: str = "regex"
    _rx: re.Pattern = field(init=False, repr=False)

    def __post_init__(self) -> None:
        f = 0
        if "i" in self.flags:
            f |= re.IGNORECASE
        if "s" in self.flags:
            f |= re.DOTALL
        if "m" in self.flags:
            f |= re.MULTILINE
        self._rx = re.compile(self.pattern, f)

    def match(self, text: str, ctx: MatchContext) -> MatchResult:
        m = self._rx.search(text)
        if not m:
            return MatchResult(False, 0.0, self.tier, self.name)
        return MatchResult(True, 1.0, self.tier, self.name, detail=f"regex /{self.pattern}/ matched {m.group(0)[:80]!r}")


@dataclass
class StringsMatcher:
    """YARA-style string set: match `min_count` of the given strings (default: any)."""

    strings: list[str]
    min_count: int = 1
    nocase: bool = True
    tier: str = "deterministic"
    name: str = "strings"

    def match(self, text: str, ctx: MatchContext) -> MatchResult:
        hay = text.lower() if self.nocase else text
        hits = [s for s in self.strings if (s.lower() if self.nocase else s) in hay]
        ok = len(hits) >= self.min_count
        return MatchResult(
            ok, len(hits) / max(len(self.strings), 1), self.tier, self.name,
            detail=f"strings matched {hits}" if ok else "",
        )
