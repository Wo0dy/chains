r"""Native Suricata / Snort rule evaluation over protocol events.

A rule such as

    alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Beacon"; flow:established,to_server;
        http.method; content:"POST"; http.uri; content:"/gate.php"; endswith; http.user_agent;
        content:"Mozilla/4.0"; depth:11; classtype:trojan-activity; sid:2000001; rev:3;)

is parsed into a header (protocol, addresses, ports, direction) and a list of
option keywords, and evaluated by `SuricataDetection.matches(event)` against
the protocol fields an EVE-style event carries. Each sticky buffer maps to a
list of field aliases (`http.uri` -> fields.http.url, fields.c-uri, fields.url
...), so events from different sensors and from Chain's own tool bridge work.

Content and pcre keep Snort's position semantics (depth / offset / distance /
within / startswith / endswith / isdataat, R flag on pcre). What stays out:
raw payload matching (content or pcre with no buffer), byte_test / byte_jump /
byte_extract, lua, dsize-only rules and protocols with no app-layer fields.
Those raise `SuricataUnsupported`, and the importer delegates the rule to a
real Suricata, matching its alerts on fields.alert.signature_id.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from .schema import Event


class SuricataUnsupported(ValueError):
    pass


class SuricataSyntax(ValueError):
    pass


# ---------------------------------------------------------------- buffers
# sticky buffer / legacy modifier -> field aliases, tried in order (dotted paths into event.fields)
BUFFERS: dict[str, list[str]] = {
    "http.uri": ["http.url", "http.uri", "c-uri", "url", "uri", "request_uri"],
    "http.uri.raw": ["http.url", "http.uri", "c-uri", "url", "uri"],
    "http.host": ["http.hostname", "http.host", "cs-host", "DestinationHostname", "host", "hostname"],
    "http.host.raw": ["http.hostname", "http.host", "cs-host", "DestinationHostname", "host", "hostname"],
    "http.user_agent": ["http.http_user_agent", "http.user_agent", "cs-user-agent", "user_agent", "UserAgent"],
    "http.method": ["http.http_method", "http.method", "cs-method", "method"],
    "http.header": ["http.request_headers", "http.headers", "http.header", "headers"],
    "http.header.raw": ["http.request_headers", "http.headers", "http.header", "headers"],
    "http.header_names": ["http.header_names", "header_names"],
    "http.cookie": ["http.cookie", "cs-cookie", "cookie"],
    "http.referer": ["http.http_refer", "http.referer", "cs-referer", "referer"],
    "http.request_body": ["http.request_body", "request_body", "body", "cs-body"],
    "http.response_body": ["http.response_body", "response_body", "sc-body"],
    "http.stat_code": ["http.status", "http.stat_code", "sc-status", "status", "status_code"],
    "http.stat_msg": ["http.stat_msg", "status_message"],
    "http.content_type": ["http.http_content_type", "http.content_type", "content_type", "cs-content-type"],
    "http.content_len": ["http.length", "http.content_len", "content_length"],
    "http.protocol": ["http.protocol", "protocol_version"],
    "http.request_line": ["http.request_line", "request_line"],
    "http.response_line": ["http.response_line", "response_line"],
    "http.start": ["http.request_start", "http.start"],
    "http.accept": ["http.accept"], "http.accept_lang": ["http.accept_lang"], "http.accept_enc": ["http.accept_enc"],
    "http.connection": ["http.connection"], "http.location": ["http.location"], "http.server": ["http.server"],
    "http.response_header": ["http.response_headers"],
    "dns.query": ["dns.rrname", "dns.query", "QueryName", "query", "rrname", "dns.queries"],
    "dns.query.name": ["dns.rrname", "dns.query", "QueryName", "query", "rrname"],
    "dns.answer.name": ["dns.answer", "dns.answers"],
    "tls.sni": ["tls.sni", "sni", "server_name", "DestinationHostname"],
    "tls.cert_subject": ["tls.subject", "tls.cert_subject", "subject"],
    "tls.cert_issuer": ["tls.issuerdn", "tls.cert_issuer", "issuer"],
    "tls.cert_serial": ["tls.serial", "tls.cert_serial"],
    "tls.cert_fingerprint": ["tls.fingerprint", "tls.cert_fingerprint"],
    "tls.certs": ["tls.certs", "tls.chain"],
    "tls.version": ["tls.version"],
    "ja3.hash": ["tls.ja3.hash", "ja3.hash", "ja3", "ja3_hash"],
    "ja3.string": ["tls.ja3.string", "ja3.string"],
    "ja3s.hash": ["tls.ja3s.hash", "ja3s.hash", "ja3s"],
    "ja3s.string": ["tls.ja3s.string"],
    "ja4.hash": ["tls.ja4", "ja4.hash", "ja4"],
    "file.name": ["fileinfo.filename", "file.name", "filename", "TargetFilename"],
    "file.data": ["fileinfo.data", "file.data", "content"],
    "file.magic": ["fileinfo.magic", "file.magic"],
    "ssh.proto": ["ssh.client.proto_version", "ssh.proto"],
    "ssh.software": ["ssh.client.software_version", "ssh.software"],
    "ssh.hassh": ["ssh.client.hassh.hash", "ssh.hassh"],
    "smtp.helo": ["smtp.helo"], "smtp.mail_from": ["smtp.mail_from"], "smtp.rcpt_to": ["smtp.rcpt_to"],
    "email.from": ["email.from"], "email.to": ["email.to"], "email.subject": ["email.subject"],
    "smb.named_pipe": ["smb.named_pipe"], "smb.share": ["smb.share"], "smb.ntlmssp.user": ["smb.ntlmssp.user"],
    "krb5.cname": ["krb5.cname"], "krb5.sname": ["krb5.sname"],
    "snmp.community": ["snmp.community"],
    "sip.method": ["sip.method"], "sip.uri": ["sip.uri"],
    "mqtt.publish.topic": ["mqtt.publish.topic"],
    "ftp.command": ["ftp.command"],
    "quic.sni": ["quic.sni"], "quic.ua": ["quic.ua"],
    "ike.vendor": ["ike.vendor"],
}
LEGACY = {
    "http_uri": "http.uri", "http_raw_uri": "http.uri.raw", "http_header": "http.header", "http_raw_header": "http.header.raw",
    "http_cookie": "http.cookie", "http_raw_cookie": "http.cookie", "http_method": "http.method", "http_client_body": "http.request_body",
    "http_server_body": "http.response_body", "http_host": "http.host", "http_raw_host": "http.host.raw",
    "http_user_agent": "http.user_agent", "http_stat_code": "http.stat_code", "http_stat_msg": "http.stat_msg",
    "dns_query": "dns.query", "tls_sni": "tls.sni", "tls_cert_subject": "tls.cert_subject", "tls_cert_issuer": "tls.cert_issuer",
    "file_data": "file.data", "ja3_hash": "ja3.hash", "ja3s_hash": "ja3s.hash", "ssh_proto": "ssh.proto", "ssh_software": "ssh.software",
    "http.server_body": "http.response_body", "http.client_body": "http.request_body", "http.raw_uri": "http.uri.raw",
}
PCRE_BUFFER_FLAGS = {"U": "http.uri", "I": "http.uri.raw", "H": "http.header", "D": "http.header.raw", "C": "http.cookie",
                     "M": "http.method", "P": "http.request_body", "Q": "http.response_body", "V": "http.user_agent",
                     "W": "http.host", "Z": "http.host.raw", "S": "http.stat_code", "Y": "http.stat_msg"}
TRANSFORMS = {"to_lowercase", "to_uppercase", "strip_whitespace", "compress_whitespace", "dotprefix", "url_decode", "header_lowercase"}

PROTOCOL_EVENT = {
    "http": "net.http", "http1": "net.http", "http2": "net.http", "dns": "net.dns", "tls": "net.tls", "ssl": "net.tls",
    "smb": "net.smb", "ftp": "net.ftp", "ftp-data": "net.ftp", "smtp": "net.smtp", "ssh": "net.ssh", "krb5": "net.kerberos",
    "snmp": "net.snmp", "sip": "net.sip", "mqtt": "net.mqtt", "nfs": "net.nfs", "dcerpc": "net.dcerpc", "rdp": "net.rdp",
    "ike": "net.ike", "quic": "net.quic", "dhcp": "net.dhcp", "ntp": "net.ntp", "tftp": "net.tftp", "modbus": "net.modbus",
    "dnp3": "net.dnp3", "enip": "net.enip", "imap": "net.imap", "pop3": "net.pop3", "rfb": "net.rfb", "websocket": "net.websocket",
    "ldap": "net.ldap", "pgsql": "net.pgsql", "mysql": "net.mysql", "bittorrent-dht": "net.bittorrent", "mdns": "net.mdns",
    "tcp": "net.flow", "udp": "net.flow", "ip": "net.flow", "icmp": "net.flow", "sctp": "net.flow", "ip6": "net.flow", "icmpv6": "net.flow",
    "tcp-pkt": "net.flow", "tcp-stream": "net.flow", "pkthdr": "net.anomaly", "ipv4": "net.flow", "ipv6": "net.flow",
    "igmp": "net.flow", "gre": "net.flow", "vlan": "net.flow", "ppp": "net.flow", "ethernet": "net.flow",
}
# Buffers that live on a specific protocol: a tcp rule using http.uri is really an http rule.
BUFFER_PROTOCOL = {b: b.split(".", 1)[0] for b in BUFFERS}
BUFFER_PROTOCOL.update({k: "tls" for k in BUFFERS if k.startswith(("ja3", "ja4"))})
BUFFER_PROTOCOL.update({k: "file" for k in BUFFERS if k.startswith("file.")})
BUFFER_PROTOCOL.update({k: "smtp" for k in BUFFERS if k.startswith("email.")})

# Default rule variables (suricata.yaml defaults). Override via SuricataDetection vars / importer variables.
DEFAULT_VARS: dict[str, str] = {
    "HOME_NET": "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]", "EXTERNAL_NET": "!$HOME_NET",
    "HTTP_SERVERS": "$HOME_NET", "SMTP_SERVERS": "$HOME_NET", "SQL_SERVERS": "$HOME_NET", "DNS_SERVERS": "$HOME_NET",
    "TELNET_SERVERS": "$HOME_NET", "AIM_SERVERS": "$EXTERNAL_NET", "DC_SERVERS": "$HOME_NET", "DNP3_SERVER": "$HOME_NET",
    "DNP3_CLIENT": "$HOME_NET", "MODBUS_CLIENT": "$HOME_NET", "MODBUS_SERVER": "$HOME_NET", "ENIP_CLIENT": "$HOME_NET",
    "ENIP_SERVER": "$HOME_NET",
    "HTTP_PORTS": "80", "SHELLCODE_PORTS": "!80", "ORACLE_PORTS": "1521", "SSH_PORTS": "22", "DNP3_PORTS": "20000",
    "MODBUS_PORTS": "502", "FILE_DATA_PORTS": "[$HTTP_PORTS,110,143]", "FTP_PORTS": "21", "GENEVE_PORTS": "6081",
    "VXLAN_PORTS": "4789", "TEREDO_PORTS": "3544", "SIP_PORTS": "[5060,5061]", "VNC_PORTS": "5900",
}
ADDR_FIELDS = {"src": ["src_ip", "SourceIp", "src", "source_ip", "saddr", "id.orig_h"],
               "dst": ["dest_ip", "DestinationIp", "dst", "dst_ip", "destination_ip", "daddr", "id.resp_h"]}
PORT_FIELDS = {"src": ["src_port", "SourcePort", "sport", "source_port", "id.orig_p"],
               "dst": ["dest_port", "DestinationPort", "dport", "dst_port", "destination_port", "id.resp_p"]}
SEVERITY = {"critical": "critical", "major": "high", "minor": "medium", "informational": "info", "audit": "info"}
CLASSTYPE_SEVERITY = {
    "trojan-activity": "high", "command-and-control": "critical", "targeted-activity": "critical", "exploit-kit": "high",
    "domain-c2": "critical", "credential-theft": "critical", "coin-mining": "high", "attempted-admin": "high",
    "attempted-user": "high", "successful-admin": "critical", "successful-user": "critical", "web-application-attack": "high",
    "shellcode-detect": "critical", "malware-cnc": "critical", "attempted-recon": "medium", "policy-violation": "medium",
    "bad-unknown": "medium", "misc-attack": "medium", "web-application-activity": "low", "misc-activity": "low",
    "not-suspicious": "info", "unknown": "medium", "protocol-command-decode": "low", "external-ip-check": "low",
    "pup-activity": "medium", "social-engineering": "medium", "denial-of-service": "high", "attempted-dos": "high",
    "network-scan": "medium", "default-login-attempt": "high", "suspicious-login": "medium", "system-call-detect": "medium",
    "unusual-client-port-connection": "low", "non-standard-protocol": "low", "suspicious-filename-detect": "medium",
    "string-detect": "low", "icmp-event": "info", "tcp-connection": "info",
}


# ---------------------------------------------------------------- parsing
@dataclass
class Rule:
    action: str
    proto: str
    src: str
    sport: str
    direction: str
    dst: str
    dport: str
    options: list[tuple[str, str | None]]   # (keyword, value or None), in order
    raw: str = ""

    def opt(self, key: str) -> str | None:
        for k, v in self.options:
            if k == key:
                return v
        return None

    def opts(self, key: str) -> list[str | None]:
        return [v for k, v in self.options if k == key]


_HEADER = re.compile(r"^\s*(?:#\s*)?(alert|drop|reject|pass|log|rejectsrc|rejectdst|rejectboth)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$", re.S)


def parse_rule(text: str) -> Rule:
    text = text.strip()
    m = _HEADER.match(text)
    if not m:
        raise SuricataSyntax("not a rule header")
    action, proto, src, sport, direction, dst, dport, body = m.groups()
    options: list[tuple[str, str | None]] = []
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        j = i
        while j < n and body[j] not in ":;":
            j += 1
        key = body[i:j].strip()
        if j >= n:
            raise SuricataSyntax(f"unterminated option {key!r}")
        if body[j] == ";":
            options.append((key, None))
            i = j + 1
            continue
        # value: may be quoted; a ';' inside quotes or escaped with \ does not end it
        k = j + 1
        buf, in_q = [], False
        while k < n:
            ch = body[k]
            if ch == "\\" and k + 1 < n and in_q:
                buf.append(body[k:k + 2])
                k += 2
                continue
            if ch == '"':
                in_q = not in_q
                buf.append(ch)
            elif ch == ";" and not in_q:
                break
            else:
                buf.append(ch)
            k += 1
        options.append((key, "".join(buf).strip()))
        i = k + 1
    r = Rule(action, proto.lower(), src, sport, direction, dst, dport, options, text)
    if r.opt("sid") is None:
        raise SuricataSyntax("rule has no sid")
    return r


def parse_file(text: str) -> list[tuple[int, str, bool]]:
    """(line number, rule text, commented out) for each rule-looking line. Continuation lines (`\\`) are joined."""
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        lineno = i + 1
        while line.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            line = line.rstrip()[:-1] + lines[i]
        i += 1
        s = line.strip()
        if not s:
            continue
        commented = s.startswith("#")
        body = s.lstrip("# ").strip()
        if re.match(r"(alert|drop|reject|pass|log)\s+\S+\s+\S+\s+\S+\s+(->|<>)\s", body):
            out.append((lineno, body, commented))
    return out


# ---------------------------------------------------------------- content values
_PIPE = re.compile(r"\|([0-9A-Fa-f\s]*)\|")


def content_bytes(value: str) -> bytes:
    """`"abc|20 41|\\"x\\;"` -> bytes. Pipes hold hex, backslash escapes ; " \\ : and |."""
    v = value.strip()
    if v.startswith('"') and v.endswith('"'):
        v = v[1:-1]
    out = bytearray()
    i = 0
    while i < len(v):
        ch = v[i]
        if ch == "\\" and i + 1 < len(v):
            out += v[i + 1].encode("latin-1")
            i += 2
        elif ch == "|":
            m = _PIPE.match(v, i)
            if not m:
                raise SuricataSyntax(f"bad hex in content {value!r}")
            out += bytes.fromhex(m.group(1))
            i = m.end()
        else:
            out += ch.encode("latin-1", "replace")
            i += 1
    return bytes(out)


# ---------------------------------------------------------------- addresses and ports
@dataclass
class AddrSpec:
    nets: list[tuple[bool, Any]]          # (negated, ip_network | "any")

    def matches(self, ip: str | None) -> bool:
        if ip is None:
            return False
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return False
        positive = [n for neg, n in self.nets if not neg]
        negative = [n for neg, n in self.nets if neg]
        if any(n != "any" and addr in n for n in negative):
            return False
        if not positive:                      # only negations: everything else
            return True
        return any(n == "any" or addr in n for n in positive)


@dataclass
class PortSpec:
    ranges: list[tuple[bool, int, int]]    # (negated, lo, hi); any = (False, 0, 65535)

    def matches(self, port: Any) -> bool:
        try:
            p = int(port)
        except (TypeError, ValueError):
            return False
        if any(neg and lo <= p <= hi for neg, lo, hi in self.ranges):
            return False
        pos = [(lo, hi) for neg, lo, hi in self.ranges if not neg]
        return not pos or any(lo <= p <= hi for lo, hi in pos)


def _split_list(s: str) -> list[str]:
    s = s.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def resolve_addr(spec: str, variables: dict[str, str], notes: list[str], _depth: int = 0) -> AddrSpec:
    if _depth > 8:
        raise SuricataSyntax("address variable recursion")
    nets: list[tuple[bool, Any]] = []
    for item in _split_list(spec):
        neg = item.startswith("!")
        item = item.lstrip("!")
        if item.startswith("$"):
            name = item[1:]
            if name not in variables:
                notes.append(f"address variable ${name} unknown; treated as any")
                nets.append((neg, "any"))
                continue
            inner = resolve_addr(variables[name], variables, notes, _depth + 1)
            nets += [(neg != n, net) for n, net in inner.nets]
        elif item.lower() == "any":
            nets.append((neg, "any"))
        elif item.startswith("["):
            inner = resolve_addr(item, variables, notes, _depth + 1)
            nets += [(neg != n, net) for n, net in inner.nets]
        else:
            try:
                nets.append((neg, ipaddress.ip_network(item, strict=False)))
            except ValueError as e:
                raise SuricataSyntax(f"bad address {item!r}: {e}") from e
    return AddrSpec(nets)


def resolve_port(spec: str, variables: dict[str, str], notes: list[str], _depth: int = 0) -> PortSpec:
    if _depth > 8:
        raise SuricataSyntax("port variable recursion")
    ranges: list[tuple[bool, int, int]] = []
    for item in _split_list(spec):
        neg = item.startswith("!")
        item = item.lstrip("!")
        if item.startswith("$"):
            name = item[1:]
            if name not in variables:
                notes.append(f"port variable ${name} unknown; treated as any")
                ranges.append((neg, 0, 65535))
                continue
            inner = resolve_port(variables[name], variables, notes, _depth + 1)
            ranges += [(neg != n, lo, hi) for n, lo, hi in inner.ranges]
        elif item.lower() == "any":
            ranges.append((neg, 0, 65535))
        elif item.startswith("["):
            inner = resolve_port(item, variables, notes, _depth + 1)
            ranges += [(neg != n, lo, hi) for n, lo, hi in inner.ranges]
        elif ":" in item:
            lo, hi = item.split(":", 1)
            ranges.append((neg, int(lo or 0), int(hi or 65535)))
        else:
            p = int(item)
            ranges.append((neg, p, p))
    return PortSpec(ranges)


# ---------------------------------------------------------------- detection
@dataclass
class Op:
    kind: str                     # content | pcre | bsize | isdataat | startswith | endswith
    value: Any = None
    negate: bool = False
    nocase: bool = False
    depth: int | None = None
    offset: int | None = None
    distance: int | None = None
    within: int | None = None
    relative: bool = False
    flags: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": self.kind}
        if self.kind in ("content",):
            d["value"] = self.value.decode("latin-1")
        elif self.value is not None:
            d["value"] = self.value
        for k in ("negate", "nocase", "relative"):
            if getattr(self, k):
                d[k] = True
        for k in ("depth", "offset", "distance", "within"):
            if getattr(self, k) is not None:
                d[k] = getattr(self, k)
        if self.flags:
            d["flags"] = self.flags
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Op":
        o = cls(d["kind"])
        if o.kind == "content":
            o.value = d["value"].encode("latin-1")
        else:
            o.value = d.get("value")
        for k in ("negate", "nocase", "relative", "depth", "offset", "distance", "within", "flags"):
            if k in d:
                setattr(o, k, d[k])
        return o


@dataclass
class Buffer:
    name: str
    ops: list[Op] = field(default_factory=list)
    transforms: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"buffer": self.name, "ops": [o.to_dict() for o in self.ops]}
        if self.transforms:
            d["transforms"] = list(self.transforms)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Buffer":
        return cls(d["buffer"], [Op.from_dict(o) for o in d["ops"]], list(d.get("transforms", [])))


def _get(event: Event, path: str) -> Any:
    v = event.get("fields." + path)
    if v is None and "." not in path:
        v = event.fields.get(path)
    return v


def _buffer_value(event: Event, name: str) -> bytes | None:
    for alias in BUFFERS.get(name, [name]):
        v = _get(event, alias)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            parts = []
            for x in v:
                if isinstance(x, dict):
                    parts.append(": ".join(str(y) for y in x.values()) if "name" not in x else f"{x.get('name')}: {x.get('value', '')}")
                else:
                    parts.append(str(x))
            v = "\r\n".join(parts)
        if isinstance(v, dict):
            v = "\r\n".join(f"{k}: {x}" for k, x in v.items())
        if isinstance(v, (bytes, bytearray)):
            return bytes(v)
        return str(v).encode("latin-1", "replace")
    return None


def _transform(data: bytes, transforms: list[str]) -> bytes:
    for t in transforms:
        if t == "to_lowercase":
            data = data.lower()
        elif t == "to_uppercase":
            data = data.upper()
        elif t == "strip_whitespace":
            data = re.sub(rb"\s+", b"", data)
        elif t == "compress_whitespace":
            data = re.sub(rb"\s+", b" ", data)
        elif t == "dotprefix":
            data = b"." + data
        elif t == "header_lowercase":
            data = re.sub(rb"(?m)^([^:\r\n]+):", lambda m: m.group(1).lower() + b":", data)
        elif t == "url_decode":
            from urllib.parse import unquote_to_bytes
            data = unquote_to_bytes(data.replace(b"+", b" "))
    return data


def _run_buffer(data: bytes, buf: Buffer) -> bool:
    """Snort/Suricata position semantics over one buffer."""
    data = _transform(data, buf.transforms)
    cursor = 0                       # end of the previous positive match
    for op in buf.ops:
        if op.kind == "bsize":
            lo, hi = op.value
            if not (lo <= len(data) <= hi):
                return False
            continue
        if op.kind == "isdataat":
            n, rel = op.value, op.relative
            ok = (cursor + n if rel else n) < len(data)
            if ok == op.negate:
                return False
            continue
        if op.kind == "startswith":
            continue                 # applied to the preceding content below
        if op.kind == "content":
            value = op.value
            flags = re.I if op.nocase else 0
            pat = re.compile(re.escape(value), flags | re.S)
            start = 0
            end = len(data)
            if op.distance is not None or op.relative:
                start = cursor + (op.distance or 0)
            if op.offset is not None:
                start = max(start, op.offset)
            if op.within is not None:
                end = min(end, cursor + (op.distance or 0) + op.within)
            if op.depth is not None:
                end = min(end, (op.offset or 0) + op.depth) if op.distance is None else min(end, start + op.depth)
            if op.flags == "startswith":
                m = pat.match(data, start)
                if m and m.end() > end:
                    m = None
            elif op.flags == "endswith":
                m = None
                for cand in pat.finditer(data, start):
                    if cand.end() == len(data) and cand.end() <= end:
                        m = cand
                        break
            else:
                m = pat.search(data, start, max(start, end)) if start <= len(data) else None
            found = m is not None
            if found == op.negate:
                return False
            if found:
                cursor = m.end()
            continue
        if op.kind == "pcre":
            flags = re.S if "s" in op.flags else 0
            if "i" in op.flags:
                flags |= re.I
            if "m" in op.flags:
                flags |= re.M
            try:
                pat = re.compile(op.value.encode("latin-1"), flags)
            except re.error:
                return False
            if op.relative:                 # R: the pattern runs on the rest of the buffer, so ^ means "at the cursor"
                m = pat.search(data[cursor:])
                base = cursor
            else:
                m = pat.search(data)
                base = 0
            found = m is not None
            if found == op.negate:
                return False
            if found:
                cursor = base + m.end()
            continue
    return True


class SuricataDetection:
    """A compiled Suricata rule evaluated against protocol events."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.sid = str(spec.get("sid", ""))
        self.buffers = [Buffer.from_dict(b) for b in spec.get("buffers", [])]
        self.events = list(spec.get("events", []))
        self.header = spec.get("header", {})
        self._src = AddrSpec([(n, "any" if v == "any" else ipaddress.ip_network(v)) for n, v in self.header.get("src", [])])
        self._dst = AddrSpec([(n, "any" if v == "any" else ipaddress.ip_network(v)) for n, v in self.header.get("dst", [])])
        self._sport = PortSpec([tuple(x) for x in self.header.get("sport", [])])
        self._dport = PortSpec([tuple(x) for x in self.header.get("dport", [])])
        self.bidirectional = bool(self.header.get("bidirectional"))
        self.fields = dict(spec.get("fields", {}))     # exact-value keywords: dns.opcode, tls.version ...

    def _header_ok(self, event: Event) -> bool:
        def addr(side: str) -> str | None:
            for a in ADDR_FIELDS[side]:
                v = _get(event, a)
                if v is not None:
                    return str(v)
            return None

        def port(side: str) -> Any:
            for p in PORT_FIELDS[side]:
                v = _get(event, p)
                if v is not None:
                    return v
            return None

        def check(src_ip, src_port, dst_ip, dst_port) -> bool:
            # The header is a routing filter: an event that doesn't carry an address or port can't fail on it
            # (tool-bridge and most log events have none). When it does carry one, it must match.
            return ((src_ip is None or self._src.matches(src_ip)) and
                    (dst_ip is None or self._dst.matches(dst_ip)) and
                    (src_port is None or self._sport.matches(src_port)) and
                    (dst_port is None or self._dport.matches(dst_port)))

        s, sp, d, dp = addr("src"), port("src"), addr("dst"), port("dst")
        if check(s, sp, d, dp):
            return True
        return self.bidirectional and check(d, dp, s, sp)

    @staticmethod
    def _is_any(a: AddrSpec) -> bool:
        return all(not neg and n == "any" for neg, n in a.nets) or not a.nets

    @staticmethod
    def _is_any_port(p: PortSpec) -> bool:
        return all(not neg and lo == 0 and hi == 65535 for neg, lo, hi in p.ranges) or not p.ranges

    def matches(self, event: Event) -> bool:
        if not self._header_ok(event):
            return False
        if self.events:
            ev = _get(event, "app_layer_event") or _get(event, "anomaly.event") or _get(event, "decode_event") \
                or _get(event, "stream_event") or _get(event, "event")
            if ev is None or str(ev) not in self.events:
                return False
        for name, expected in self.fields.items():
            v = _buffer_value(event, name)
            if v is None or v.decode("latin-1").lower() != str(expected).lower():
                return False
        for buf in self.buffers:
            data = _buffer_value(event, buf.name)
            if data is None:
                return False
            if not _run_buffer(data, buf):
                return False
        return True
