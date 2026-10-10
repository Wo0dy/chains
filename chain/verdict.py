from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .rules import ACTION_RANK, SEVERITY_RANK


@dataclass
class Evidence:
    step: str
    event_id: str
    event_type: str
    details: list[str] = field(default_factory=list)


@dataclass
class Hit:
    rule_id: str
    title: str
    severity: str
    action: str
    confidence: float
    response: list[str] = field(default_factory=list)
    tiers: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class Verdict:
    event_id: str
    hits: list[Hit] = field(default_factory=list)
    deferred: bool = False   # produced by Engine.advance_time (an absence confirmed by the clock)

    @property
    def action(self) -> str:
        if not self.hits:
            return "allow"
        return max((h.action for h in self.hits), key=ACTION_RANK.__getitem__)

    @property
    def severity(self) -> str | None:
        if not self.hits:
            return None
        return max((h.severity for h in self.hits), key=SEVERITY_RANK.__getitem__)

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def needs_approval(self) -> bool:
        return self.action == "require_approval"

    @property
    def responses(self) -> list[str]:
        out: list[str] = []
        for h in self.hits:
            out += [r for r in h.response if r not in out]
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "deferred": self.deferred,
            "action": self.action,
            "severity": self.severity,
            "responses": self.responses,
            "hits": [asdict(h) for h in self.hits],
        }

    def explain(self) -> str:
        if not self.hits:
            return f"[{self.event_id}] allow (no rules fired)"
        when = " (deferred: absence confirmed)" if self.deferred else ""
        lines = [f"[{self.event_id}] {self.action.upper()} severity={self.severity}{when}"]
        for h in self.hits:
            lines.append(f"  rule {h.rule_id} ({h.severity}, conf {h.confidence:.2f}, tiers {','.join(h.tiers) or '-'})")
            for ev in h.evidence:
                src = f"{ev.event_type} {ev.event_id}" if ev.event_id else ev.event_type
                lines.append(f"    step {ev.step} <- {src}")
                for d in ev.details:
                    lines.append(f"      - {d}")
        return "\n".join(lines)
