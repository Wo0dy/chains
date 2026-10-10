"""Chain event schema.

One schema covers classic security telemetry (files, processes, network,
email, logs) and AI/agent telemetry (prompts, retrievals, tool calls,
memory writes). Every piece of content carries provenance and a trust level,
which is what makes taint and context rules possible.
"""
from __future__ import annotations

import time
import uuid
from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Trust(IntEnum):
    """Lower value = less trusted. Comparisons work: Trust.UNTRUSTED < Trust.USER."""

    UNTRUSTED = 0  # web pages, inbound email, unknown files, tool output from outside
    EXTERNAL = 1   # known third party (partner API, signed vendor content)
    USER = 2       # the human operator / authenticated user
    SYSTEM = 3     # system prompt, platform config, signed internal binaries

    @classmethod
    def parse(cls, value: "Trust | str | int") -> "Trust":
        if isinstance(value, Trust):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).upper()]


class Domain(str):
    """Event domains. Kept as plain strings so new domains need no code change."""

    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    EMAIL = "email"
    AUTH = "auth"
    LOG = "log"
    AI = "ai"


# Common event types (free-form strings are allowed too).
EVENT_TYPES = {
    # classic
    "email.attachment", "file.create", "file.exec", "file.scan",
    "process.start", "process.capability", "net.flow", "net.dns",
    "auth.login", "auth.mfa", "log.raw",
    # ai / agent
    "ai.prompt", "ai.retrieval", "ai.tool_call", "ai.tool_result",
    "ai.memory_write", "ai.output",
}


class Span(BaseModel):
    """A piece of content with provenance."""

    text: str
    source: str = "unknown"          # e.g. "web:example.com", "email:inbound", "user"
    trust: Trust = Trust.UNTRUSTED

    model_config = {"arbitrary_types_allowed": True}

    @field_validator("trust", mode="before")
    @classmethod
    def _trust(cls, v: Any) -> Trust:
        return Trust.parse(v)


class ToolCall(BaseModel):
    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    dest: str | None = None          # destination host/recipient, if any
    dest_external: bool = False


class Event(BaseModel):
    """A single observation from any sensor or harness hook."""

    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    type: str                                    # e.g. "ai.tool_call", "process.start"
    ts: float = Field(default_factory=time.time)
    session_id: str = "default"                  # agent session, or investigation scope
    host: str | None = None
    user: str | None = None
    agent_id: str | None = None
    step: int | None = None

    spans: list[Span] = Field(default_factory=list)
    tool: ToolCall | None = None

    # Provenance graph edges: artifact ids this event read and produced.
    # e.g. inputs=["file:sha256:ab12"], outputs=["proc:4242"]
    inputs: list[str] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)

    # Free-form fields for classic telemetry (Sigma-style log fields,
    # process capabilities, flow stats, file metadata ...).
    fields: dict[str, Any] = Field(default_factory=dict)

    @property
    def domain(self) -> str:
        return self.type.split(".", 1)[0]

    @property
    def trust(self) -> Trust:
        """Event trust = least-trusted span. Events with no spans default to field 'trust' or SYSTEM."""
        if self.spans:
            return min(s.trust for s in self.spans)
        raw = self.fields.get("trust")
        return Trust.parse(raw) if raw is not None else Trust.SYSTEM

    @property
    def text(self) -> str:
        """All content of the event, for content matchers."""
        parts = [s.text for s in self.spans]
        if self.tool:
            parts.extend(str(v) for v in self.tool.args.values())
        for key in ("command_line", "cmdline", "CommandLine", "url", "query", "subject",
                    "body", "message", "content", "strings"):
            if key in self.fields:
                parts.append(str(self.fields[key]))
        return "\n".join(parts)

    def get(self, path: str, default: Any = None) -> Any:
        """Dotted-path field access: 'tool.name', 'fields.parent_image', 'trust', 'host'."""
        if path == "trust":
            return self.trust
        if path == "domain":
            return self.domain
        if path == "text":
            return self.text
        obj: Any = self
        for part in path.split("."):
            if obj is None:
                return default
            if isinstance(obj, BaseModel):
                if part in type(obj).model_fields:
                    obj = getattr(obj, part)
                elif isinstance(obj, Event) and part in obj.fields:
                    obj = obj.fields[part]
                else:
                    return default
            elif isinstance(obj, dict):
                obj = obj.get(part, default)
            else:
                return default
        return obj
