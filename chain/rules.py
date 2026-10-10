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
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from .importers.sigma import SigmaDetection
from .matchers import MatchExpr

ACTION_RANK = {"allow": 0, "alert": 1, "redact": 2, "require_approval": 3, "block": 4}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Step(BaseModel):
    name: str
    event: list[str] = Field(default_factory=lambda: ["*"])
    where: dict[str, Any] = Field(default_factory=dict)
    match: dict[str, Any] | None = None
    tainted_by: str | None = None
    min_attribution: float = 0.0       # require copy-through evidence, not just context taint
    same: list[str] = Field(default_factory=list)  # fields that must equal the previous step's event

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("event", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> list[str]:
        return [v] if isinstance(v, str) else list(v)

    def type_matches(self, event_type: str) -> bool:
        return any(fnmatch.fnmatchcase(event_type, p) for p in self.event)


class Window(BaseModel):
    seconds: float | None = None
    steps: int | None = None


class Rule(BaseModel):
    id: str
    title: str = ""
    description: str = ""
    severity: str = "medium"
    action: str = "alert"
    response: list[str] = Field(default_factory=list)
    confidence: float = 0.8
    tags: list[str] = Field(default_factory=list)
    group_by: str = "session_id"
    window: Window = Field(default_factory=Window)
    sequence: list[Step]
    tests: list[dict[str, Any]] = Field(default_factory=list)
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
        self.match = MatchExpr(step.match) if step.match else None
        self.rare_keys = [(c.get("by", "host"), c["field"]) for k, c in step.where.items() if k == "rare"]


class CompiledRule:
    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        self.steps = [CompiledStep(s) for s in rule.sequence]
        names = [s.name for s in rule.sequence]
        if len(set(names)) != len(names):
            raise ValueError(f"{rule.id}: step names must be unique")
        for s in rule.sequence:
            if s.tainted_by and s.tainted_by not in names[: names.index(s.name)]:
                raise ValueError(f"{rule.id}: step {s.name} tainted_by unknown/later step {s.tainted_by!r}")

    @property
    def id(self) -> str:
        return self.rule.id


def load_rule(data: dict[str, Any], source: str | None = None) -> CompiledRule:
    rule = Rule(**data, source_file=source)
    return CompiledRule(rule)


def load_rules(path: str | Path) -> list[CompiledRule]:
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.rglob("*.y*ml"))
    rules = []
    for f in files:
        for doc in yaml.safe_load_all(f.read_text()):
            if doc:
                rules.append(load_rule(doc, str(f)))
    return rules
