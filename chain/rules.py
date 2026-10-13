"""Chain rule language: model, loader and compiler.

A rule is a sequence of one or more steps. Single-step rules replace Sigma/YARA
rules; multi-step rules express attack chains across events, hosts and domains.

    id: phish_to_ransomware
    severity: critical
    action: alert            # allow | alert | redact | require_approval | block
    response: [isolate_host] # SOAR actions handed to the harness
    group_by: host           # state key for sequences (default: session_id)
    window: {seconds: 7200, steps: 50}
    sequence:
      - name: attach
        event: email.attachment
        where: {trust: untrusted}
      - name: run
        event: file.exec
        tainted_by: attach          # provenance: must descend from step `attach`
        where: {fields.signed: false}
      - name: impact
        event: process.capability
        tainted_by: attach
        where: {fields.capabilities: [encrypt_bulk, delete_shadow_copies]}

Two step modifiers cover what single-event matching can't:

    count: {min: 5, within: 300, distinct: fields.dest_port}
        the step completes once `min` matching events (or distinct values of
        `distinct`) are seen within `within` seconds

    absent: true
        "not followed by". In the middle of a sequence, the partial dies if this
        event happens before the next step. As the last step it needs
        `within: <seconds>` and fires once that time passes with no such event
        (resolved by Engine.advance_time).
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from .importers.sigma import SigmaDetection
from .yara import compile_detection
from .matchers import MatchExpr

ACTION_RANK = {"allow": 0, "alert": 1, "redact": 2, "require_approval": 3, "block": 4}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _seconds(v: Any) -> Any:
    """Accept `within: 300` or `within: {seconds: 300}`."""
    return v.get("seconds") if isinstance(v, dict) else v


class Count(BaseModel):
    min: int = Field(ge=2)
    within: float = Field(gt=0)                  # seconds, sliding
    distinct: str | None = None                  # count distinct values of this field instead of events

    @field_validator("within", mode="before")
    @classmethod
    def _within(cls, v: Any) -> Any:
        return _seconds(v)


class Step(BaseModel):
    name: str
    event: list[str] = Field(default_factory=lambda: ["*"])
    where: dict[str, Any] = Field(default_factory=dict)
    match: dict[str, Any] | None = None
    tainted_by: str | None = None
    min_attribution: float = 0.0       # require copy-through evidence, not just context taint
    same: list[str] = Field(default_factory=list)  # fields that must equal the previous step's event
    count: Count | None = None
    absent: bool = False
    within: float | None = None        # seconds; only on a final absent step

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("within", mode="before")
    @classmethod
    def _within(cls, v: Any) -> Any:
        return _seconds(v)

    @field_validator("event", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> list[str]:
        return [v] if isinstance(v, str) else list(v)

    def type_matches(self, event_type: str) -> bool:
        return any(fnmatch.fnmatchcase(event_type, p) for p in self.event)


class Window(BaseModel):
    seconds: float | None = None
    steps: int | None = None


class Origin(BaseModel):
    """Where a corpus rule came from and how faithfully it converted."""

    source: str                          # manifest name, e.g. sigmahq
    format: str                          # sigma | yara | suricata | chain
    path: str                            # path inside the upstream repo
    ref: str = ""                        # pinned upstream commit
    upstream_id: str = ""
    upstream_sha256: str = ""            # hash of the upstream file, to detect changes
    license: str = ""
    fidelity: str = "exact"              # exact | lossy | delegated
    notes: list[str] = Field(default_factory=list)   # what was lost or approximated
    status: str | None = None            # upstream lifecycle: stable, test, experimental, deprecated ...
    logsource: dict[str, Any] = Field(default_factory=dict)
    falsepositives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    native: str | None = None            # original rule text for delegated rules
    upstream_name: str | None = None     # Sigma `name:` (what correlation rules reference)

    @field_validator("fidelity")
    @classmethod
    def _fidelity(cls, v: str) -> str:
        if v not in ("exact", "lossy", "delegated"):
            raise ValueError("fidelity must be exact, lossy or delegated")
        return v


class Rule(BaseModel):
    id: str
    title: str = ""
    description: str = ""
    severity: str = "medium"
    action: str = "alert"
    response: list[str] = Field(default_factory=list)
    confidence: float = 0.8
    tags: list[str] = Field(default_factory=list)
    group_by: str | list[str] | None = "session_id"   # one field, several (composite key) or None (global)
    window: Window = Field(default_factory=Window)
    sequence: list[Step]
    tests: list[dict[str, Any]] = Field(default_factory=list)
    origin: Origin | None = None
    source_file: str | None = None

    @field_validator("action")
    @classmethod
    def _action(cls, v: str) -> str:
        if v not in ACTION_RANK:
            raise ValueError(f"action must be one of {list(ACTION_RANK)}")
        return v

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        if v not in SEVERITY_RANK:
            raise ValueError(f"severity must be one of {list(SEVERITY_RANK)}")
        return v


class CompiledStep:
    def __init__(self, step: Step) -> None:
        self.spec = step
        self.where = dict(step.where)
        if "sigma" in self.where:
            self.where["sigma"] = SigmaDetection(self.where["sigma"]["detection"])
        if "yara" in self.where and isinstance(self.where["yara"], dict):
            self.where["yara"] = compile_detection(self.where["yara"])
        self.match = MatchExpr(step.match) if step.match else None
        self.rare_keys = [(c.get("by", "host"), c["field"]) for k, c in step.where.items() if k == "rare"]


class CompiledRule:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.steps = [CompiledStep(s) for s in rule.sequence]
        names = [s.name for s in rule.sequence]
        if len(set(names)) != len(names):
            raise ValueError(f"{rule.id}: step names must be unique")
        absent = {s.name for s in rule.sequence if s.absent}
        for i, s in enumerate(rule.sequence):
            if s.tainted_by and s.tainted_by not in names[:i]:
                raise ValueError(f"{rule.id}: step {s.name} tainted_by unknown/later step {s.tainted_by!r}")
            if s.tainted_by in absent:
                raise ValueError(f"{rule.id}: step {s.name} can't be tainted_by absent step {s.tainted_by!r}")
            if s.absent:
                last = i == len(rule.sequence) - 1
                if i == 0:
                    raise ValueError(f"{rule.id}: absent step {s.name} can't be the first step")
                if rule.sequence[i - 1].absent:
                    raise ValueError(f"{rule.id}: absent step {s.name} can't follow another absent step")
                if s.count:
                    raise ValueError(f"{rule.id}: absent step {s.name} can't also count")
                if last and not s.within:
                    raise ValueError(f"{rule.id}: final absent step {s.name} needs within: <seconds>")
                if not last and s.within is not None:
                    raise ValueError(f"{rule.id}: within only applies to a final absent step ({s.name})")
            elif s.within is not None:
                raise ValueError(f"{rule.id}: within on step {s.name} needs absent: true (use count.within to count)")

    @property
    def id(self) -> str:
        return self.rule.id

    @property
    def group_fields(self) -> tuple[str, ...]:
        gb = self.rule.group_by
        if gb is None:
            return ()
        return (gb,) if isinstance(gb, str) else tuple(gb)


def load_rule(data: dict[str, Any], source: str | None = None) -> CompiledRule:
    rule = Rule(**data, source_file=source)
    return CompiledRule(rule)


def load_rules(path: str | Path) -> list[CompiledRule]:
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.rglob("*.y*ml"))
    rules = []
    for f in files:
        for doc in yaml.load_all(f.read_text(), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
            if doc:
                rules.append(load_rule(doc, str(f)))
    return rules
