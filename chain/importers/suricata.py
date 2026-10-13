"""Suricata / Snort import: rules become Chain rules evaluated natively by chain.suricata.

Exact: header + app-layer buffers (http.*, dns.*, tls.*, ja3/ja4, file.*, ...)
with content / pcre / bsize / isdataat / startswith / endswith and the
usual transforms; app-layer-event rules; threshold / detection_filter as
count steps; flowbits isset/set as a two-step sequence when the setting
rule is in the same source.

Delegated (kept with native text, matched on fields.alert.signature_id):
raw payload content or pcre with no buffer, byte_test / byte_jump /
byte_extract, lua, dsize, protocols without app-layer fields.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..suricata import (BUFFERS, BUFFER_PROTOCOL, CLASSTYPE_SEVERITY, DEFAULT_VARS, LEGACY, PCRE_BUFFER_FLAGS,
                        PROTOCOL_EVENT, SEVERITY, TRANSFORMS, Buffer, Op, Rule, SuricataDetection, SuricataSyntax,
                        SuricataUnsupported, content_bytes, parse_file, parse_rule, resolve_addr, resolve_port)

IGNORED = {"msg", "sid", "rev", "gid", "classtype", "reference", "metadata", "priority", "flow", "flowint", "target",
           "noalert", "tag", "xbits", "hostbits", "iprep", "geoip", "datarep", "dataset", "requires", "config"}
PAYLOAD_ONLY = {"byte_test", "byte_jump", "byte_extract", "byte_math", "lua", "luajit", "dsize", "base64_decode",
                "base64_data", "replace", "pkt_data", "ip_proto", "ttl", "tos", "id", "ipopts", "fragbits", "fragoffset",
                "window", "seq", "ack", "flags", "itype", "icode", "icmp_id", "icmp_seq", "rpc", "stream_size", "asn1",
                "entropy", "sameip", "fast_pattern_only", "prefilter", "engine-event", "tcp.hdr", "udp.hdr", "ipv4.hdr", "ipv6.hdr", "tcp.mss", "tcp.flags", "ip.opts",
                "frame", "vlan.id", "vlan.layers", "bytes", "urilen", "tcpv4.hdr"}
STICKY_INT = {"dns.opcode", "tls.version", "http.stat_code", "ssh.proto", "sip.method"}
METADATA_RE = re.compile(r"\s*([\w.-]+)\s+([^,]+?)\s*(?:,|$)")


@dataclass
class SuricataImport:
    sid: str
    rule: dict[str, Any]
    source: str
    delegated: bool = False
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    flowbits_set: list[str] = field(default_factory=list)
    flowbits_isset: list[str] = field(default_factory=list)


def _metadata(r: Rule) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for v in r.opts("metadata"):
        for k, val in METADATA_RE.findall(v or ""):
            out.setdefault(k, []).append(val.strip())
    return out


def _severity(r: Rule, meta: dict[str, list[str]]) -> str:
    sev = (meta.get("signature_severity") or [""])[0].lower()
    if sev in SEVERITY:
        return SEVERITY[sev]
    ct = (r.opt("classtype") or "").lower()
    return CLASSTYPE_SEVERITY.get(ct, "medium")


def _msg(r: Rule) -> str:
    m = r.opt("msg") or ""
    return m.strip().strip('"')


def _shell(r: Rule, meta: dict[str, list[str]], suffix: str = "") -> dict[str, Any]:
    sid = r.opt("sid")
    tags = ["imported:suricata"]
    if r.opt("classtype"):
        tags.append(f"classtype:{r.opt('classtype')}")
    for t in meta.get("mitre_technique_id", []):
        tags.append(f"attack:{t}")
    for t in meta.get("tag", []):
        tags.append(f"et:{t}")
    for fam in meta.get("malware_family", []):
        tags.append(f"malware:{fam}")
    return {
        "id": f"suricata_{sid}",
        "title": _msg(r) + suffix,
        "description": f"Suricata rule sid {sid} rev {r.opt('rev') or '?'}; action {r.action}, protocol {r.proto}",
        "severity": _severity(r, meta),
        "action": "alert",
        "tags": tags,
    }


def _event_type(proto: str, buffers: list[Buffer]) -> str:
    protos = {BUFFER_PROTOCOL.get(b.name, proto) for b in buffers}
    if len(protos) == 1:
        p = protos.pop()
        if p == "file":
            return "file.scan"
        if p in PROTOCOL_EVENT:
            return PROTOCOL_EVENT[p]
        return f"net.{p}"
    if len(protos) > 1:
        raise SuricataUnsupported(f"buffers from several protocols: {sorted(protos)}")
    if proto not in PROTOCOL_EVENT:
        raise SuricataUnsupported(f"protocol {proto!r}")
    return PROTOCOL_EVENT[proto]


def _parse_threshold(value: str) -> dict[str, Any]:
    d: dict[str, Any] = {}
    for part in value.split(","):
        k, _, v = part.strip().partition(" ")
        d[k.strip()] = v.strip()
    return d


def convert(r: Rule, variables: dict[str, str] | None = None) -> SuricataImport:
    """One parsed rule -> SuricataImport (exact or delegated)."""
    variables = {**DEFAULT_VARS, **(variables or {})}
    notes: list[str] = []
    meta = _metadata(r)
    sid = r.opt("sid") or ""
    src_spec = resolve_addr(r.src, variables, notes)
    dst_spec = resolve_addr(r.dst, variables, notes)
    sport_spec = resolve_port(r.sport, variables, notes)
    dport_spec = resolve_port(r.dport, variables, notes)
    header = {
        "src": [(neg, "any" if n == "any" else str(n)) for neg, n in src_spec.nets],
        "dst": [(neg, "any" if n == "any" else str(n)) for neg, n in dst_spec.nets],
        "sport": [list(x) for x in sport_spec.ranges],
        "dport": [list(x) for x in dport_spec.ranges],
        "bidirectional": r.direction == "<>",
    }

    buffers: list[Buffer] = []
    current: Buffer | None = None
    events: list[str] = []
    fields: dict[str, Any] = {}
    count: dict[str, Any] | None = None
    group_by: Any = None
    rate_limit: str | None = None     # alert de-duplication (threshold type limit): changes alert volume, not detection
    flow_set: list[str] = []
    flow_isset: list[str] = []
    last_content: Op | None = None
    unsupported: list[str] = []
    payload: list[Op] = []            # contents seen before any buffer; a legacy modifier may still claim them
    noalert = False

    def buf(name: str) -> Buffer:
        nonlocal current
        if current is None or current.name != name or current.ops:
            if current is not None and current.name == name and not current.ops:
                return current
            current = Buffer(name)
            buffers.append(current)
        return current

    i = 0
    opts = r.options
    while i < len(opts):
        key, value = opts[i]
        i += 1
        k = key.strip()
        if k in IGNORED:
            if k == "flow" and value and "to_client" in value and r.proto in ("http", "tcp") and not buffers:
                pass
            continue
        if k in BUFFERS and value is None:                       # sticky buffer
            current = Buffer(k)
            buffers.append(current)
            continue
        if k in LEGACY and value is None:                        # legacy modifier on the previous content
            target = LEGACY[k]
            if last_content is None:
                raise SuricataSyntax(f"{k} without a preceding content")
            # move the last content into the target buffer
            for b in buffers:
                if last_content in b.ops:
                    b.ops.remove(last_content)
            if last_content in payload:
                payload.remove(last_content)
            tb = next((b for b in reversed(buffers) if b.name == target), None)
            if tb is None:
                tb = Buffer(target)
                buffers.append(tb)
            tb.ops.append(last_content)
            current = tb
            continue
        if k in TRANSFORMS and value is None:
            if current is None:
                unsupported.append(f"{k} on the payload")
                continue
            current.transforms.append(k)
            continue
        if k == "content":
            if value is None:
                raise SuricataSyntax("content without a value")
            negate = value.lstrip().startswith("!")
            op = Op("content", content_bytes(value.lstrip("! ").strip()), negate=negate)
            if current is None:
                payload.append(op)
                last_content = op
                continue
            current.ops.append(op)
            last_content = op
            continue
        if k == "nocase":
            if last_content is not None:
                last_content.nocase = True
            continue
        if k in ("depth", "offset", "distance", "within"):
            if last_content is None or value is None:
                continue
            try:
                setattr(last_content, k, int(value))
            except ValueError:
                unsupported.append(f"{k} with a variable ({value})")
            continue
        if k in ("startswith", "endswith"):
            if last_content is not None:
                last_content.flags = k
            continue
        if k in ("fast_pattern", "fast_pattern_only"):
            continue
        if k == "isdataat":
            if current is None or value is None:
                unsupported.append("isdataat on the payload")
                continue
            parts = [p.strip() for p in value.split(",")]
            neg = parts[0].startswith("!")
            n = int(parts[0].lstrip("!"))
            current.ops.append(Op("isdataat", n, negate=neg, relative="relative" in parts[1:]))
            continue
        if k == "bsize":
            if current is None or value is None:
                unsupported.append("bsize on the payload")
                continue
            v = value.strip()
            m = re.fullmatch(r"(<>|<=|>=|<|>|=)?\s*(\d+)(?:\s*<>\s*(\d+))?", v)
            if not m:
                raise SuricataSyntax(f"bad bsize {value!r}")
            op_, a, b = m.group(1) or "=", int(m.group(2)), m.group(3)
            if b is not None:
                lo, hi = a + 1, int(b) - 1
            elif op_ == "<":
                lo, hi = 0, a - 1
            elif op_ == "<=":
                lo, hi = 0, a
            elif op_ == ">":
                lo, hi = a + 1, 10 ** 9
            elif op_ == ">=":
                lo, hi = a, 10 ** 9
            else:
                lo, hi = a, a
            current.ops.append(Op("bsize", [lo, hi]))
            continue
        if k == "urilen":
            # urilen applies to http.uri whatever the current buffer
            v = (value or "").strip().replace("norm", "").replace("raw", "").strip(", ")
            m = re.fullmatch(r"(<>|<=|>=|<|>)?\s*(\d+)(?:\s*<>\s*(\d+))?", v)
            if not m:
                unsupported.append(f"urilen {value}")
                continue
            op_, a, b = m.group(1) or "=", int(m.group(2)), m.group(3)
            lo, hi = (a + 1, int(b) - 1) if b else (0, a - 1) if op_ == "<" else (0, a) if op_ == "<=" else \
                (a + 1, 10 ** 9) if op_ == ">" else (a, 10 ** 9) if op_ == ">=" else (a, a)
            ub = next((x for x in buffers if x.name == "http.uri"), None) or Buffer("http.uri")
            if ub not in buffers:
                buffers.append(ub)
            ub.ops.append(Op("bsize", [lo, hi]))
            continue
        if k == "pcre":
            if value is None:
                raise SuricataSyntax("pcre without a value")
            v = value.strip()
            negate = v.startswith("!")
            v = v.lstrip("!").strip().strip('"')
            if not v.startswith("/"):
                raise SuricataSyntax(f"bad pcre {value!r}")
            end = v.rindex("/")
            pattern, flags = v[1:end], v[end + 1:]
            target = current
            buffer_flags = [f for f in flags if f in PCRE_BUFFER_FLAGS]
            if buffer_flags:
                target = next((b for b in reversed(buffers) if b.name == PCRE_BUFFER_FLAGS[buffer_flags[0]]), None)
                if target is None:
                    target = Buffer(PCRE_BUFFER_FLAGS[buffer_flags[0]])
                    buffers.append(target)
                current = target
            if target is None:
                unsupported.append("pcre on the raw payload")
                continue
            try:
                re.compile(pattern.encode("latin-1"))
            except (re.error, UnicodeEncodeError) as e:
                raise SuricataUnsupported(f"pcre not compatible with Python re: {e}") from e
            target.ops.append(Op("pcre", pattern, negate=negate, relative="R" in flags,
                                 flags="".join(f for f in flags if f in "ism")))
            continue
        if k in ("app-layer-event", "decode-event", "decode_event", "stream-event"):
            events.append((value or "").strip())
            continue
        if k in STICKY_INT and value is not None:
            fields[k] = value.strip().strip('"')
            continue
        if k in ("threshold", "detection_filter"):
            d = _parse_threshold(value or "")
            ttype = d.get("type", "threshold" if k == "detection_filter" else "")
            cnt, secs, track = int(d.get("count", 0) or 0), int(d.get("seconds", 0) or 0), d.get("track", "by_src")
            if ttype in ("limit", "backoff") or (ttype == "both" and cnt < 2):
                rate_limit = (value or "").strip()
                continue
            if cnt >= 2 and secs > 0:
                minimum = cnt + 1 if k == "detection_filter" else cnt
                count = {"min": minimum, "within": float(secs)}
                group_by = "fields.src_ip" if track == "by_src" else "fields.dest_ip" if track == "by_dst" else None
                if ttype == "both":
                    rate_limit = (value or "").strip()
            elif cnt > 0:
                notes.append(f"{k} with count {cnt} below 2 or no seconds: ignored")
            continue
        if k == "flowbits":
            parts = [p.strip() for p in (value or "").split(",")]
            cmd = parts[0] if parts else ""
            if cmd == "set" and len(parts) > 1:
                flow_set.append(parts[1])
            elif cmd == "isset" and len(parts) > 1:
                flow_isset.append(parts[1])
            elif cmd == "isnotset":
                notes.append(f"flowbits isnotset {parts[1] if len(parts) > 1 else ''} ignored")
            elif cmd == "noalert":
                noalert = True
            continue
        if k in PAYLOAD_ONLY:
            unsupported.append(k)
            continue
        if k.endswith((".hdr", ".flags")) or k.startswith(("byte_", "tcp.", "udp.", "ip.", "icmp.")):
            unsupported.append(k)
            continue
        if k in BUFFERS and value is not None:          # e.g. http.stat_code:200 shorthand
            fields[k] = value.strip().strip('"')
            continue
        unsupported.append(f"keyword {k}")

    if payload:
        unsupported.append("content on the raw payload")
    if unsupported:
        raise SuricataUnsupported("; ".join(dict.fromkeys(unsupported)))

    event_type: Any = _event_type(r.proto, buffers)
    if not buffers and not events and not fields and event_type == "net.flow":
        raise SuricataUnsupported("header-only rule on a transport protocol (needs packet data)")
    if events:
        # engine anomaly events arrive as EVE `anomaly` records, or inline on the protocol event
        event_type = ["net.anomaly", event_type] if event_type != "net.anomaly" else event_type

    spec: dict[str, Any] = {"sid": sid, "header": header, "buffers": [b.to_dict() for b in buffers]}
    if events:
        spec["events"] = events
    if fields:
        spec["fields"] = fields
    SuricataDetection(spec)        # validate
    step: dict[str, Any] = {"name": "match", "event": event_type, "where": {"suricata": spec}}
    if count:
        step["count"] = count
    rule = _shell(r, meta)
    rule["sequence"] = [step]
    if count:
        rule["group_by"] = group_by
    if r.action == "pass":
        rule["action"] = "allow"
    if r.action in ("drop", "reject", "rejectsrc", "rejectdst", "rejectboth"):
        rule["action"] = "block"
    if noalert:
        rule["action"] = "allow"
    imp = SuricataImport(sid, rule, r.raw, notes=notes, meta={"metadata": meta, "classtype": r.opt("classtype"),
                                                               "rev": r.opt("rev"), "references": r.opts("reference"),
                                                               "rate_limit": rate_limit},
                         flowbits_set=flow_set, flowbits_isset=flow_isset)
    return imp


def _delegated(r: Rule, reason: str) -> SuricataImport:
    meta = _metadata(r)
    rule = _shell(r, meta, " (native engine)")
    rule["tags"].append("delegated:suricata")
    rule["sequence"] = [{"name": "match", "event": ["net.alert", "net.*"], "where": {"fields.alert.signature_id": int(r.opt("sid"))}}]
    return SuricataImport(r.opt("sid") or "", rule, r.raw, delegated=True,
                          notes=[f"{reason}: run with Suricata, Chain matches fields.alert.signature_id"], meta={"metadata": meta})


def suricata_import(text: str, variables: dict[str, str] | None = None, include_disabled: bool = False) -> list[SuricataImport]:
    """Convert every rule in a .rules file. Disabled (commented) rules are skipped unless asked for."""
    out = []
    for lineno, body, commented in parse_file(text):
        if commented and not include_disabled:
            continue
        try:
            r = parse_rule(body)
        except SuricataSyntax as e:
            out.append(SuricataImport("", {}, body, delegated=True, notes=[f"not parsed (line {lineno}): {e}"]))
            continue
        try:
            imp = convert(r, variables)
        except SuricataUnsupported as e:
            imp = _delegated(r, f"unsupported: {e}")
        except SuricataSyntax as e:
            imp = _delegated(r, f"not parsed: {e}")
        imp.meta["line"] = lineno
        if commented:
            imp.meta["disabled"] = True
        out.append(imp)
    return out


def link_flowbits(imports: list[SuricataImport]) -> None:
    """Turn `flowbits:isset,X` into a two-step sequence (setter then this rule) grouped by flow, when the
    setting rule is in the same source. Otherwise the condition is dropped with a lossy note."""
    setters: dict[str, SuricataImport] = {}
    for imp in imports:
        for name in imp.flowbits_set:
            setters.setdefault(name, imp)
    for imp in imports:
        if imp.delegated or not imp.flowbits_isset:
            continue
        steps = []
        for name in imp.flowbits_isset:
            setter = setters.get(name)
            if setter is None or setter.delegated:
                imp.notes.append(f"flowbits isset {name}: setting rule not in this source; condition dropped")
                continue
            step = dict(setter.rule["sequence"][0])
            step["name"] = f"flowbit_{re.sub(r'[^A-Za-z0-9_]+', '_', name)}"
            steps.append(step)
        if steps:
            own = imp.rule["sequence"][0]
            own["name"] = "match"
            imp.rule["sequence"] = steps + [own]
            imp.rule["group_by"] = ["fields.flow_id"]
            imp.rule.setdefault("window", {"seconds": 3600})
