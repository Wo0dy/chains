"""Harness integration: emit events at hook points, enforce verdicts.

    guard = ChainGuard(engine, session_id="s1", agent_id="triage-agent")
    guard.on_prompt("summarize this pdf", trust="user")
    guard.on_retrieval(pdf_text, source="upload:invoice.pdf", trust="untrusted")
    guard.pre_tool_call("send_email", {"to": "x@evil.io", "body": ...}, dest="x@evil.io", external=True)
        -> raises ToolBlocked / ApprovalRequired, or returns the Verdict

Or wrap tools directly:

    @guard.tool(external_dest=lambda args: args["to"])
    def send_email(to, body): ...
"""
from __future__ import annotations

import functools
from typing import Any, Callable

from .engine import Engine
from .schema import Event, Span, ToolCall, Trust
from .verdict import Verdict


class ToolBlocked(PermissionError):
    def __init__(self, verdict: Verdict) -> None:
        super().__init__(verdict.explain())
        self.verdict = verdict


class ApprovalRequired(PermissionError):
    def __init__(self, verdict: Verdict) -> None:
        super().__init__(verdict.explain())
        self.verdict = verdict


class ChainGuard:
    def __init__(
        self,
        engine: Engine,
        session_id: str,
        agent_id: str | None = None,
        user: str | None = None,
        on_verdict: Callable[[Verdict], None] | None = None,
        enforce: bool = True,
    ) -> None:
        self.engine = engine
        self.session_id = session_id
        self.agent_id = agent_id
        self.user = user
        self.on_verdict = on_verdict
        self.enforce = enforce
        self._step = 0

    def _emit(self, type_: str, **kw: Any) -> Verdict:
        self._step += 1
        ev = Event(type=type_, session_id=self.session_id, agent_id=self.agent_id,
                   user=self.user, step=self._step, **kw)
        verdict = self.engine.evaluate(ev)
        if self.on_verdict and verdict.hits:
            self.on_verdict(verdict)
        return verdict

    def _span(self, text: str, source: str, trust: Trust | str) -> list[Span]:
        return [Span(text=text, source=source, trust=Trust.parse(trust))]

    # --------------------------------------------------------------- hook points
    def on_prompt(self, text: str, trust: Trust | str = "user", source: str = "user") -> Verdict:
        return self._emit("ai.prompt", spans=self._span(text, source, trust))

    def on_retrieval(self, text: str, source: str, trust: Trust | str = "untrusted") -> Verdict:
        return self._emit("ai.retrieval", spans=self._span(text, source, trust))

    def on_tool_result(self, tool: str, text: str, trust: Trust | str = "untrusted") -> Verdict:
        return self._emit("ai.tool_result", spans=self._span(text, f"tool:{tool}", trust))

    def on_memory_write(self, text: str) -> Verdict:
        return self._emit("ai.memory_write", spans=self._span(text, "agent", "system"))

    def on_output(self, text: str) -> Verdict:
        return self._emit("ai.output", spans=self._span(text, "agent", "system"))

    def pre_tool_call(self, name: str, args: dict[str, Any], dest: str | None = None,
                      external: bool = False) -> Verdict:
        verdict = self._emit("ai.tool_call", tool=ToolCall(name=name, args=args, dest=dest, dest_external=external),
                             fields={"trust": "system"})
        if self.enforce:
            if verdict.blocked:
                raise ToolBlocked(verdict)
            if verdict.needs_approval:
                raise ApprovalRequired(verdict)
        return verdict

    # --------------------------------------------------------------- decorator
    def tool(self, name: str | None = None, external_dest: Callable[[dict], str | None] | None = None,
             is_external: Callable[[str | None], bool] = lambda d: d is not None):
        def deco(fn):
            tool_name = name or fn.__name__

            @functools.wraps(fn)
            def wrapper(**kwargs):
                dest = external_dest(kwargs) if external_dest else None
                self.pre_tool_call(tool_name, kwargs, dest=dest, external=is_external(dest))
                result = fn(**kwargs)
                self.on_tool_result(tool_name, str(result))
                return result

            return wrapper

        return deco
