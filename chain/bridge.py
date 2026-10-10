"""Tool-to-event bridge: express an agent's tool call as the classic event it is about to cause.

An agent running `powershell -enc ...` through a `run_shell` tool is, to a
SOC, a process creation. Thousands of Sigma rules know what that command
means, but they watch `process.start` events, and an agent harness only
emits `ai.tool_call`. The bridge produces the classic event too, so the whole
corpus applies to agent actions, with the session's taint carried across.

    bridge = ToolBridge()                       # default mappings
    bridge.register("deploy_*", my_builder)     # add your own

    for ev in bridge.events("run_shell", {"cmd": "powershell -enc AAAA"}):
        ...  # Event(type="process.start", fields={"CommandLine": ..., "Image": ...})

Builders get (tool name, args) and return a list of dicts with at least
`type` and `fields`; the guard fills in session, user, host and the
provenance edge back to the tool call.
"""
from __future__ import annotations

import fnmatch
import re
import shlex
import sys
from typing import Any, Callable
from urllib.parse import urlparse

Builder = Callable[[str, dict[str, Any]], list[dict[str, Any]]]

# Argument names tools commonly use for the same thing, in preference order.
ARG_ALIASES = {
    "command": ["cmd", "command", "cmdline", "command_line", "script", "code", "args", "input"],
    "url": ["url", "uri", "href", "endpoint", "address", "link"],
    "path": ["path", "file", "filename", "file_path", "filepath", "target", "dest", "destination", "name"],
    "host": ["host", "hostname", "domain", "name", "server"],
    "method": ["method", "verb"],
}

WINDOWS_PATHS = {"powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 "pwsh.exe": r"C:\Program Files\PowerShell\7\pwsh.exe"}


def host_platform() -> str:
    return {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")


def arg(args: dict[str, Any], kind: str) -> Any:
    for k in ARG_ALIASES[kind]:
        if k in args and args[k] not in (None, ""):
            return args[k]
    return None


def _image(command: str, platform: str) -> tuple[str, bool]:
    """Executable path from a command line. Sigma rules expect a full path (`Image|endswith: \\powershell.exe`),
    so when the tool gives only a name a conventional install path is synthesised and flagged as such."""
    try:
        first = shlex.split(command, posix=platform != "windows")[0]
    except (ValueError, IndexError):
        first = command.split()[0] if command.split() else ""
    if "/" in first or "\\" in first:
        return first, False
    base = first
    if platform == "windows":
        if "." not in base:
            base += ".exe"          # cmd builtins (dir, copy ...) run inside cmd.exe; everything else is an .exe
        return WINDOWS_PATHS.get(base.lower(), rf"C:\Windows\System32\{base}"), True
    return f"/usr/bin/{base}", True


# ------------------------------------------------------------------ default builders
def shell(tool: str, args: dict[str, Any], platform: str = "linux") -> list[dict[str, Any]]:
    command = arg(args, "command")
    if command is None:
        return []
    if isinstance(command, (list, tuple)):
        command = " ".join(str(c) for c in command)
    command = str(command)
    image, synthesised = _image(command, platform)
    parent = r"C:\Program Files\Agent\agent.exe" if platform == "windows" else "/usr/bin/agent"
    return [{
        "type": "process.start",
        "fields": {"CommandLine": command, "command_line": command, "Image": image, "image_synthesised": synthesised,
                   "ParentImage": parent, "via_tool": tool},
        "outputs": [f"proc:{tool}:{abs(hash(command)) & 0xFFFFFFFF:x}"],
    }]


def http(tool: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    url = arg(args, "url")
    if not url:
        return []
    url = str(url)
    u = urlparse(url if "://" in url else "http://" + url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    method = str(arg(args, "method") or ("POST" if "post" in tool.lower() else "GET")).upper()
    events = [{
        "type": "net.flow",
        "fields": {"DestinationHostname": host, "DestinationPort": port, "Initiated": "true",
                   "Image": "agent", "url": url, "via_tool": tool},
    }, {
        "type": "net.http",
        "fields": {"c-uri": u.path or "/", "cs-host": host, "cs-method": method, "url": url,
                   "DestinationHostname": host, "via_tool": tool},
    }]
    if host and not re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host, re.I):
        events.append({"type": "net.dns", "fields": {"QueryName": host, "query": host, "Image": "agent", "via_tool": tool}})
    return events


def file_write(tool: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    path = arg(args, "path")
    if not path:
        return []
    return [{"type": "file.create",
             "fields": {"TargetFilename": str(path), "Image": "agent", "via_tool": tool},
             "outputs": [f"file:{path}"]}]


def file_delete(tool: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    path = arg(args, "path")
    if not path:
        return []
    return [{"type": "file.delete", "fields": {"TargetFilename": str(path), "Image": "agent", "via_tool": tool}}]


def dns(tool: str, args: dict[str, Any]) -> list[dict[str, Any]]:
    host = arg(args, "host") or arg(args, "url")
    if not host:
        return []
    return [{"type": "net.dns", "fields": {"QueryName": str(host), "query": str(host), "Image": "agent", "via_tool": tool}}]


DEFAULT_MAPPINGS: list[tuple[str, Builder]] = [
    ("*shell*", shell), ("*bash*", shell), ("*exec*", shell), ("*run_command*", shell), ("*run_cmd*", shell),
    ("*powershell*", shell), ("*cmd*", shell), ("*subprocess*", shell), ("*terminal*", shell), ("*execute*", shell),
    ("*http*", http), ("*fetch*", http), ("*curl*", http), ("*request*", http), ("*browse*", http), ("*web_*", http),
    ("*download*", http), ("*webhook*", http),
    ("*write_file*", file_write), ("*save_file*", file_write), ("*create_file*", file_write), ("*write*", file_write),
    ("*delete_file*", file_delete), ("*remove_file*", file_delete), ("*rm*", file_delete),
    ("*dns*", dns), ("*resolve*", dns), ("*nslookup*", dns),
]


class ToolBridge:
    def __init__(self, mappings: list[tuple[str, Builder]] | None = None, defaults: bool = True,
                 platform: str | None = None) -> None:
        """`platform` is where the agent's tools run: windows, linux or macos (default: this host).
        It is stamped on every bridged event so platform-specific corpus rules only see their own."""
        self.mappings: list[tuple[str, Builder]] = list(mappings or [])
        if defaults:
            self.mappings += DEFAULT_MAPPINGS
        self.platform = platform or host_platform()

    def register(self, pattern: str, builder: Builder) -> None:
        """Add a mapping checked before the defaults. `pattern` is a glob on the tool name."""
        self.mappings.insert(0, (pattern, builder))

    def events(self, tool: str, args: dict[str, Any]) -> list[dict[str, Any]]:
        """Classic events for one tool call, or [] if the tool maps to nothing."""
        low = tool.lower()
        for pattern, builder in self.mappings:
            if fnmatch.fnmatchcase(low, pattern):
                out = builder(tool, dict(args), self.platform) if builder is shell else builder(tool, dict(args))
                for ev in out:
                    ev.setdefault("fields", {}).setdefault("platform", self.platform)
                return out
        return []
