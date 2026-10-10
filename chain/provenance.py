"""Provenance and taint tracking.

Taint answers: "did untrusted content influence this event?"

Two propagation paths:

1. Artifact edges (classic + AI). An untrusted event taints its outputs.
   Any event consuming a tainted artifact inherits the taint and passes it
   to its own outputs. This follows email -> file -> process -> network.

2. Context (AI only). LLMs can't tell us which input caused which output,
   so we taint conservatively: once untrusted content enters an agent
   session's context, every later AI event in that session is tainted.
   Attribution (does the tool argument actually contain the tainted text?)
   is computed separately and reported as evidence strength.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .normalize import canonical
from .schema import Event, Trust

UNTRUSTED_THRESHOLD = Trust.EXTERNAL  # events at or below this trust start a taint
MIN_OVERLAP = 12                      # chars of shared text that count as attribution


@dataclass
class TaintInfo:
    sources: set[str] = field(default_factory=set)   # event ids that originated the taint
    via: dict[str, str] = field(default_factory=dict)  # source id -> "artifact:<id>" | "context" | "self"


class ProvenanceTracker:
    def __init__(self) -> None:
        self._artifact_taint: dict[str, set[str]] = defaultdict(set)   # artifact -> source event ids
        self._context_taint: dict[str, set[str]] = defaultdict(set)    # session -> source event ids
        self._source_text: dict[str, str] = {}                         # source event id -> canonical text
        self._events: dict[str, Event] = {}

    # ------------------------------------------------------------------ record
    def record(self, event: Event) -> TaintInfo:
        """Compute this event's taint, then propagate it to its outputs/context."""
        info = TaintInfo()

        if event.trust <= UNTRUSTED_THRESHOLD:
            info.sources.add(event.id)
            info.via[event.id] = "self"
            self._source_text[event.id] = canonical(event.text)

        for art in event.inputs:
            for src in self._artifact_taint.get(art, ()):
                info.sources.add(src)
                info.via.setdefault(src, f"artifact:{art}")

        if event.domain == "ai":
            for src in self._context_taint.get(event.session_id, ()):
                info.sources.add(src)
                info.via.setdefault(src, "context")

        for art in event.outputs:
            self._artifact_taint[art] |= info.sources
        if event.domain == "ai":
            self._context_taint[event.session_id] |= info.sources

        self._events[event.id] = event
        return info

    # ------------------------------------------------------------- attribution
    def attribution(self, event: Event, source_id: str) -> float:
        """0..1 strength that `event` content actually derives from `source_id` content.

        Uses longest shared substring between the source's text and the event's
        content (tool args included). 1.0 = strong copy-through, 0.0 = only
        conservative context taint.
        """
        src_text = self._source_text.get(source_id)
        if not src_text:
            return 0.0
        target = canonical(event.text)
        if not target:
            return 0.0
        overlap = _longest_common_substring(src_text.lower(), target.lower())
        if overlap < MIN_OVERLAP:
            return 0.0
        return min(1.0, overlap / max(MIN_OVERLAP * 3, 1))

    def is_tainted_by(self, info: TaintInfo, source_id: str) -> bool:
        return source_id in info.sources

    def event(self, event_id: str) -> Event | None:
        return self._events.get(event_id)


def _longest_common_substring(a: str, b: str, cap: int = 4000) -> int:
    a, b = a[:cap], b[:cap]
    if not a or not b:
        return 0
    prev = [0] * (len(b) + 1)
    best = 0
    for ch_a in a:
        cur = [0] * (len(b) + 1)
        for j, ch_b in enumerate(b, 1):
            if ch_a == ch_b:
                cur[j] = prev[j - 1] + 1
                if cur[j] > best:
                    best = cur[j]
        prev = cur
    return best
