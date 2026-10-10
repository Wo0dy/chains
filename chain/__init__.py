"""Chain: a semantic, context-aware detection language for classic and agentic security."""
from .engine import Engine
from .hooks import ApprovalRequired, ChainGuard, ToolBlocked
from .rules import load_rule, load_rules
from .schema import Event, Span, ToolCall, Trust
from .verdict import Verdict

__version__ = "0.1.0"
__all__ = ["Engine", "ChainGuard", "ToolBlocked", "ApprovalRequired", "load_rule", "load_rules",
           "Event", "Span", "ToolCall", "Trust", "Verdict"]
