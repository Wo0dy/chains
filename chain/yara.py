r"""Native YARA evaluation over file content.

A `.yar` file is parsed into rules (meta, strings, condition). Strings become
byte regexes (text with ascii / wide / nocase / fullword / xor / base64, hex
with wildcards, jumps and alternatives, regex with i / s), and the condition
is parsed into an AST that `YaraDetection.matches(event)` evaluates against
the event's content (`fields.content` as a latin-1 string or bytes, or
`fields.content_b64`).

What stays out: module calls (pe., math., hash., elf., dotnet. ...),
`entrypoint`, `wide` on regex strings and huge xor expansions. Those raise
`YaraUnsupported` at compile time and the importer delegates the rule to
yara-python instead.
"""
from __future__ import annotations

import base64
import math
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Callable

from .schema import Event

MODULES = {"pe", "elf", "math", "hash", "dotnet", "cuckoo", "magic", "time", "console", "string", "macho", "dex", "lnk"}
EXTERNALS = ("filename", "filepath", "extension", "filetype", "owner")
MAX_PATTERN = 60_000     # bytes of regex source after xor / base64 expansion
WORD = rb"[A-Za-z0-9_]"


class YaraUnsupported(ValueError):
    pass


class YaraSyntax(ValueError):
    pass


# ================================================================ file parsing
@dataclass
class YString:
    id: str                 # without the leading $ ("" for anonymous)
    kind: str               # text | regex | hex
    value: str              # as written (text escapes unprocessed, hex body, regex body)
    modifiers: list[str] = field(default_factory=list)
    regex_flags: str = ""   # i / s on regex strings

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "kind": self.kind, "value": self.value}
        if self.modifiers:
            d["modifiers"] = list(self.modifiers)
        if self.regex_flags:
            d["regex_flags"] = self.regex_flags
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "YString":
        return cls(d["id"], d["kind"], d["value"], list(d.get("modifiers", [])), d.get("regex_flags", ""))


@dataclass
class YRule:
    name: str
    strings: list[YString]
    condition: str
    meta: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    private: bool = False
    global_: bool = False
    source: str = ""        # this rule's text


_COMMENT_RE = re.compile(r'("(?:[^"\\]|\\.)*")|/\*.*?\*/|//[^\n]*', re.S)


def strip_comments(text: str) -> str:
    """Remove // and /* */ comments but keep string literals intact."""
    return _COMMENT_RE.sub(lambda m: m.group(1) or ("\n" * m.group(0).count("\n")), text)


_RULE_HEAD = re.compile(r"((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)\s*(?::\s*([^{]*?))?\s*\{")


def parse_file(text: str) -> tuple[list[YRule], list[str]]:
    """Return (rules, imports) for a YARA file.

    One pass over the original text, skipping comments and string literals, finds each
    rule header and its matching closing brace; the rule body is then comment-stripped.
    """
    imports = re.findall(r'^\s*import\s*"(\w+)"', strip_comments(text), re.M)
    rules: list[YRule] = []
    i, n = 0, len(text)
    line_start = True
    while i < n:
        ch = text[i]
        if ch == "/" and text.startswith("//", i):
            i = text.find("\n", i)
            i = n if i < 0 else i
            continue
        if ch == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if ch.isspace():
            line_start = line_start or ch == "\n"
            i += 1
            continue
        if line_start:
            m = _RULE_HEAD.match(text, i)
            if m:
                body_start = m.end()
                end = _match_brace(text, body_start)
                body = strip_comments(text[body_start:end - 1])
                rule = _parse_body(m.group(2), body)
                rule.tags = (m.group(3) or "").split()
                rule.private = "private" in m.group(1)
                rule.global_ = "global" in m.group(1)
                rule.source = text[m.start():end]
                rules.append(rule)
                i = end
                line_start = False
                continue
        line_start = False
        # skip to the next line; headers only start a line
        j = text.find("\n", i)
        i = n if j < 0 else j
    return rules, imports


def _regex_literal_starts(text: str, i: int) -> bool:
    """A `/` right after `=` or `matches` opens a regex literal (which may contain braces)."""
    before = text[max(0, i - 12):i].rstrip()
    return before.endswith("=") or before.endswith("matches")


def _match_brace(text: str, start: int) -> int:
    """Index just past the brace that closes the one before `start`, skipping strings and comments."""
    depth, i, n = 1, start, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif ch == "/" and _regex_literal_starts(text, i):
            i += 1
            while i < n and text[i] != "/":
                i += 2 if text[i] == "\\" else 1
        elif ch == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif ch == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise YaraSyntax("unbalanced braces")


_SECTION = re.compile(r"(?<![\w$])(meta|strings|condition)\s*:")
_LITERAL = re.compile(r'"(?:[^"\\]|\\.)*"')


def _masked(body: str) -> str:
    """The body with string literal contents blanked (same length), so section keywords inside strings are ignored."""
    return _LITERAL.sub(lambda m: '"' + " " * (len(m.group(0)) - 2) + '"', body)
_STRING_LINE = re.compile(
    r'\$(\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|/((?:[^/\\]|\\.)+)/([is]*)|\{([^}]*)\})\s*([^\n$]*)', re.S)
_META_LINE = re.compile(r'(\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|(true|false)|(-?(?:0x[0-9a-fA-F]+|\d+)))')


def _int(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        return int(text.lstrip("0") or "0")   # YARA accepts 0100; Python's auto-base does not


def _parse_body(name: str, body: str) -> YRule:
    parts = {"meta": "", "strings": "", "condition": ""}
    sections = list(_SECTION.finditer(_masked(body)))
    for k, m in enumerate(sections):
        end = sections[k + 1].start() if k + 1 < len(sections) else len(body)
        parts[m.group(1)] = body[m.end():end]
    if not parts["condition"].strip():
        raise YaraSyntax(f"rule {name} has no condition")
    strings = []
    anon = 0
    for m in _STRING_LINE.finditer(parts["strings"]):
        sid, text, rx, rx_flags, hx, mods = m.groups()
        if not sid:
            anon += 1
            sid = f"__anon{anon}"
        modifiers = re.findall(r"\b(nocase|wide|ascii|fullword|private|xor(?:\([^)]*\))?|base64wide(?:\([^)]*\))?|base64(?:\([^)]*\))?)", mods or "")
        if text is not None:
            strings.append(YString(sid, "text", text, modifiers))
        elif rx is not None:
            strings.append(YString(sid, "regex", rx, modifiers, rx_flags or ""))
        else:
            strings.append(YString(sid, "hex", " ".join(hx.split()), modifiers))
    meta: dict[str, Any] = {}
    for m in _META_LINE.finditer(parts["meta"]):
        key, s, b, n = m.groups()
        meta[key] = s if s is not None else (b == "true") if b is not None else _int(n)
    return YRule(name, strings, " ".join(parts["condition"].split()), meta)


# ================================================================ strings -> byte regexes
_ESC = {"n": b"\n", "t": b"\t", "r": b"\r", '"': b'"', "\\": b"\\"}


def unescape_text(value: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            if nxt == "x" and i + 3 < len(value):
                out += bytes([int(value[i + 2:i + 4], 16)])
                i += 4
                continue
            out += _ESC.get(nxt, nxt.encode("latin-1"))
            i += 2
            continue
        out += ch.encode("latin-1", "replace")
        i += 1
    return bytes(out)


def _wide(b: bytes) -> bytes:
    return b"".join(bytes([c, 0]) for c in b)


def _xor_range(mod: str) -> tuple[int, int]:
    m = re.fullmatch(r"xor(?:\(\s*(0x[0-9a-fA-F]+|\d+)\s*(?:-\s*(0x[0-9a-fA-F]+|\d+))?\s*\))?", mod)
    if not m:
        raise YaraSyntax(f"bad modifier {mod}")
    lo = int(m.group(1), 0) if m.group(1) else 0
    hi = int(m.group(2), 0) if m.group(2) else (lo if m.group(1) else 255)
    return lo, hi


def _base64_variants(raw: bytes) -> list[bytes]:
    start, end = (0, 2, 3), (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(b" " * i + raw)
        out.append(enc[start[i]:end[(len(raw) + i) % 3]])
    return out


def text_regex(s: YString) -> bytes:
    raw = unescape_text(s.value)
    mods = s.modifiers
    xor = next((m for m in mods if m.startswith("xor")), None)
    b64 = [m for m in mods if m.startswith("base64")]
    if b64 and (xor or "nocase" in mods or "fullword" in mods):
        raise YaraUnsupported("base64 combined with xor/nocase/fullword")
    forms: list[bytes] = []
    if b64:
        for m in b64:
            if "(" in m:
                raise YaraUnsupported("base64 with a custom alphabet")
            variants = _base64_variants(raw)
            forms += [_wide(v) for v in variants] if m.startswith("base64wide") else variants
    else:
        plain = [raw] if ("ascii" in mods or "wide" not in mods) else []
        if "wide" in mods:
            plain.append(_wide(raw))
        if xor:
            lo, hi = _xor_range(xor)
            if len(raw) * (hi - lo + 1) * 4 > MAX_PATTERN:
                raise YaraUnsupported("xor expansion too large")
            forms = [bytes(c ^ k for c in p) for p in plain for k in range(lo, hi + 1)]
        else:
            forms = plain
    alts = b"|".join(re.escape(f) for f in forms)
    pat = b"(?:" + alts + b")" if len(forms) > 1 else alts
    if "fullword" in mods:
        pat = b"(?<!" + WORD + b")" + pat + b"(?!" + WORD + b")"
    return pat


_HEX_TOKEN = re.compile(r"\(|\)|\||\[\s*(\d*)\s*-?\s*(\d*)\s*\]|([0-9A-Fa-f?]{2})|~")


def hex_regex(body: str) -> bytes:
    out: list[str] = []
    pos = 0
    for m in _HEX_TOKEN.finditer(body):
        if body[pos:m.start()].strip():
            raise YaraSyntax(f"bad hex string near {body[pos:m.start()]!r}")
        pos = m.end()
        tok = m.group(0)
        if tok == "(":
            out.append("(?:")
        elif tok == ")":
            out.append(")")
        elif tok == "|":
            out.append("|")
        elif tok == "~":
            raise YaraUnsupported("negated hex byte")
        elif tok.startswith("["):
            lo, hi = m.group(1), m.group(2)
            if "-" in tok:
                out.append(".{%s,%s}" % (lo or "0", hi))
            else:
                out.append(".{%s}" % lo)
        else:
            pair = m.group(3)
            if pair == "??":
                out.append(".")
            elif "?" in pair:
                base = int(pair.replace("?", "0"), 16)
                chars = "".join(r"\x%02x" % (base | (k << (4 if pair[0] == "?" else 0))) for k in range(16))
                out.append("[" + chars + "]")
            else:
                out.append(r"\x%02x" % int(pair, 16))
    if body[pos:].strip():
        raise YaraSyntax(f"bad hex string near {body[pos:]!r}")
    return "".join(out).encode("latin-1")


def regex_regex(s: YString) -> tuple[bytes, int]:
    if "wide" in s.modifiers:
        raise YaraUnsupported("wide modifier on a regex string")
    if any(m.startswith(("xor", "base64")) for m in s.modifiers):
        raise YaraUnsupported("xor/base64 on a regex string")
    pat = s.value.encode("latin-1", "replace")
    flags = re.S if "s" in s.regex_flags else 0
    if "i" in s.regex_flags or "nocase" in s.modifiers:
        flags |= re.I
    if "fullword" in s.modifiers:
        pat = b"(?<!" + WORD + b")(?:" + pat + b")(?!" + WORD + b")"
    return pat, flags


def compile_string(s: YString) -> re.Pattern[bytes]:
    try:
        if s.kind == "text":
            return re.compile(text_regex(s), re.I | re.S if "nocase" in s.modifiers else re.S)
        if s.kind == "hex":
            return re.compile(hex_regex(s.value), re.S)
        pat, flags = regex_regex(s)
        return re.compile(pat, flags | re.M)
    except re.error as e:
        raise YaraUnsupported(f"regex: {e}") from e


# ================================================================ condition parsing
_TOKEN = re.compile(r"""
    (?P<ws>\s+)
  | (?P<num>0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:KB|MB)?)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<rx>/(?:[^/\\]|\\.)+/[is]*)
  | (?P<op>\.\.|==|!=|<=|>=|<<|>>|[-+*\\%&|^~<>()\[\],:.])
  | (?P<sid>[$#@!][A-Za-z0-9_]*\*?)
  | (?P<id>[A-Za-z_][A-Za-z0-9_.]*)
""", re.X)

_KEYWORDS = {"and", "or", "not", "of", "them", "at", "in", "for", "any", "all", "none", "filesize", "entrypoint",
             "true", "false", "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith",
             "matches", "iequals", "defined"}


def tokenize(cond: str) -> list[tuple[str, str]]:
    out = []
    pos = 0
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise YaraSyntax(f"bad token near {cond[pos:pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind == "ws":
            continue
        val = m.group(kind)
        if kind == "id" and val in _KEYWORDS:
            kind = "kw"
        out.append((kind, val))
    return out


class Parser:
    """Recursive-descent parser for YARA conditions -> nested tuples."""

    def __init__(self, cond: str) -> None:
        self.toks = tokenize(cond)
        self.pos = 0

    def peek(self, n: int = 0) -> tuple[str, str] | None:
        return self.toks[self.pos + n] if self.pos + n < len(self.toks) else None

    def take(self) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise YaraSyntax("unexpected end of condition")
        self.pos += 1
        return tok

    def accept(self, kind: str, val: str | None = None) -> bool:
        tok = self.peek()
        if tok and tok[0] == kind and (val is None or tok[1] == val):
            self.pos += 1
            return True
        return False

    def expect(self, kind: str, val: str | None = None) -> str:
        tok = self.take()
        if tok[0] != kind or (val is not None and tok[1] != val):
            raise YaraSyntax(f"expected {val or kind}, got {tok[1]!r}")
        return tok[1]

    def parse(self) -> Any:
        node = self.expr()
        if self.peek() is not None:
            raise YaraSyntax(f"trailing tokens from {self.peek()[1]!r}")
        return node

    def expr(self) -> Any:
        node = self.and_expr()
        while self.accept("kw", "or"):
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self) -> Any:
        node = self.not_expr()
        while self.accept("kw", "and"):
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self) -> Any:
        if self.accept("kw", "not"):
            return ("not", self.not_expr())
        return self.comparison()

    def comparison(self) -> Any:
        left = self.bitor()
        tok = self.peek()
        if tok and tok[0] == "op" and tok[1] in ("==", "!=", "<", "<=", ">", ">="):
            self.pos += 1
            return ("cmp", tok[1], left, self.bitor())
        if tok and tok[0] == "kw" and tok[1] in ("contains", "icontains", "startswith", "istartswith", "endswith",
                                                 "iendswith", "iequals", "matches"):
            self.pos += 1
            if tok[1] == "matches":
                rx = self.expect("rx")
                return ("matches", left, rx)
            return ("strop", tok[1], left, self.bitor())
        return left

    def bitor(self) -> Any:
        node = self.bitxor()
        while self.peek() == ("op", "|"):
            self.pos += 1
            node = ("bin", "|", node, self.bitxor())
        return node

    def bitxor(self) -> Any:
        node = self.bitand()
        while self.peek() == ("op", "^"):
            self.pos += 1
            node = ("bin", "^", node, self.bitand())
        return node

    def bitand(self) -> Any:
        node = self.shift()
        while self.peek() == ("op", "&"):
            self.pos += 1
            node = ("bin", "&", node, self.shift())
        return node

    def shift(self) -> Any:
        node = self.additive()
        while self.peek() in (("op", "<<"), ("op", ">>")):
            op = self.take()[1]
            node = ("bin", op, node, self.additive())
        return node

    def additive(self) -> Any:
        node = self.term()
        while self.peek() in (("op", "+"), ("op", "-")):
            op = self.take()[1]
            node = ("bin", op, node, self.term())
        return node

    def term(self) -> Any:
        node = self.unary()
        while self.peek() in (("op", "*"), ("op", "\\"), ("op", "%")):
            op = self.take()[1]
            node = ("bin", op, node, self.unary())
        return node

    def unary(self) -> Any:
        if self.accept("op", "-"):
            return ("neg", self.unary())
        if self.accept("op", "~"):
            return ("bitnot", self.unary())
        return self.primary()

    def range_(self) -> tuple[Any, Any]:
        self.expect("op", "(")
        lo = self.expr()
        self.expect("op", "..")
        hi = self.expr()
        self.expect("op", ")")
        return lo, hi

    def string_set(self) -> Any:
        if self.accept("kw", "them"):
            return ("them",)
        self.expect("op", "(")
        items = []
        while True:
            tok = self.take()
            if tok[0] != "sid" or not tok[1].startswith("$"):
                raise YaraSyntax(f"expected string identifier in set, got {tok[1]!r}")
            items.append(tok[1][1:])
            if not self.accept("op", ","):
                break
        self.expect("op", ")")
        return ("set", items)

    def quantifier(self) -> Any:
        if self.accept("kw", "any"):
            return ("q", "any")
        if self.accept("kw", "all"):
            return ("q", "all")
        if self.accept("kw", "none"):
            return ("q", "none")
        node = self.unary()              # not bitor(): `50% of them` must not parse % as modulo
        if self.accept("op", "%"):
            return ("q", "pct", node)
        return ("q", "n", node)

    def primary(self) -> Any:
        tok = self.take()
        kind, val = tok
        if kind == "num":
            mult = 1
            if val.endswith("KB"):
                mult, val = 1024, val[:-2]
            elif val.endswith("MB"):
                mult, val = 1024 * 1024, val[:-2]
            return ("num", (float(val) if "." in val else _int(val)) * mult)
        if kind == "str":
            return ("lit", unescape_text(val[1:-1]))
        if kind == "op" and val == "(":
            node = self.expr()
            self.expect("op", ")")
            return node
        if kind == "sid":
            return self.string_ref(val)
        if kind == "kw":
            if val == "true":
                return ("bool", True)
            if val == "false":
                return ("bool", False)
            if val == "filesize":
                return ("filesize",)
            if val == "entrypoint":
                raise YaraUnsupported("entrypoint (needs the pe module)")
            if val in ("any", "all", "none"):
                self.pos -= 1
                return self.of_expr()
            if val == "for":
                return self.for_expr()
            if val == "defined":
                return ("defined", self.unary())
            raise YaraSyntax(f"unexpected keyword {val!r}")
        if kind == "id":
            if re.fullmatch(r"u?int(8|16|32)(be)?", val):
                self.expect("op", "(")
                off = self.expr()
                self.expect("op", ")")
                return ("read", val, off)
            root = val.split(".", 1)[0]
            if root in MODULES or "." in val:
                raise YaraUnsupported(f"module reference {val}")
            if root in EXTERNALS:
                return ("ext", val)
            return ("rule", val)
        raise YaraSyntax(f"unexpected token {val!r}")

    def string_ref(self, val: str) -> Any:
        sigil, name = val[0], val[1:]
        if name.endswith("*"):
            # `$a* ` only valid inside sets; a bare one before `of` is handled by of_expr via lookahead
            raise YaraSyntax(f"wildcard string {val!r} outside a set")
        if sigil == "$":
            if self.accept("kw", "at"):
                return ("at", name, self.bitor())
            if self.accept("kw", "in"):
                lo, hi = self.range_()
                return ("in", name, lo, hi)
            return ("found", name)
        if sigil == "#":
            if self.accept("kw", "in"):
                lo, hi = self.range_()
                return ("count_in", name, lo, hi)
            return ("count", name)
        if sigil in "@!":
            idx: Any = ("num", 1)
            if self.accept("op", "["):
                idx = self.expr()
                self.expect("op", "]")
            return ("offset" if sigil == "@" else "length", name, idx)
        raise YaraSyntax(val)

    def of_expr(self) -> Any:
        q = self.quantifier()
        self.expect("kw", "of")
        sset = self.string_set()
        if self.accept("kw", "in"):
            lo, hi = self.range_()
            return ("of_in", q, sset, lo, hi)
        if self.accept("kw", "at"):
            return ("of_at", q, sset, self.bitor())
        return ("of", q, sset)

    def for_expr(self) -> Any:
        q = self.quantifier()
        if self.accept("kw", "of"):
            sset = self.string_set()
            self.expect("op", ":")
            self.expect("op", "(")
            body = self.expr()
            self.expect("op", ")")
            return ("for_strings", q, sset, body)
        var = self.expect("id")
        self.expect("kw", "in")
        if self.peek() == ("op", "("):
            # integer range or an explicit set of values
            save = self.pos
            try:
                lo, hi = self.range_()
                it: Any = ("range", lo, hi)
            except YaraSyntax:
                self.pos = save
                self.expect("op", "(")
                vals = [self.expr()]
                while self.accept("op", ","):
                    vals.append(self.expr())
                self.expect("op", ")")
                it = ("values", vals)
        else:
            raise YaraUnsupported("for over a module iterator")
        self.expect("op", ":")
        self.expect("op", "(")
        body = self.expr()
        self.expect("op", ")")
        return ("for_ints", q, var, it, body)


class _Parser2(Parser):
    """Handles `N of ($a*)` where the quantifier is a number: primary() sees a num first."""

    def comparison(self) -> Any:
        # `2 of them` / `1 of ($x*)` / `50% of them`: a number followed by `of` or `%`
        tok, nxt = self.peek(), self.peek(1)
        if tok and tok[0] == "num" and nxt and (nxt == ("kw", "of") or (nxt == ("op", "%") and self.peek(2) == ("kw", "of"))):
            return self.of_expr()
        if tok and tok[0] == "op" and tok[1] == "(" and self._paren_then_of():
            return self.of_expr()
        return super().comparison()

    def _paren_then_of(self) -> bool:
        depth, i = 0, self.pos
        while i < len(self.toks):
            k, v = self.toks[i]
            if (k, v) == ("op", "("):
                depth += 1
            elif (k, v) == ("op", ")"):
                depth -= 1
                if depth == 0:
                    return i + 1 < len(self.toks) and self.toks[i + 1] == ("kw", "of")
            i += 1
        return False


def parse_condition(cond: str) -> Any:
    return _Parser2(cond).parse()


# ================================================================ evaluation
class Undefined(Exception):
    """A YARA undefined value: comparisons involving it are false."""


@dataclass
class _Ctx:
    data: bytes
    filesize: int
    strings: dict[str, re.Pattern[bytes]]
    externals: dict[str, Any]
    rules: Callable[[str], bool]
    matches_cache: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    found_cache: dict[str, bool] = field(default_factory=dict)
    anon: str | None = None          # the string bound by `for ... of ... : ($ ...)`
    vars: dict[str, Any] = field(default_factory=dict)

    def pattern(self, name: str) -> re.Pattern[bytes]:
        if name == "":
            if self.anon is None:
                raise YaraSyntax("anonymous string outside a for loop")
            name = self.anon
        if name not in self.strings:
            raise YaraSyntax(f"unknown string ${name}")
        return self.strings[name]

    def key(self, name: str) -> str:
        return self.anon if name == "" and self.anon is not None else name

    def found(self, name: str) -> bool:
        k = self.key(name)
        if k not in self.found_cache:
            if k in self.matches_cache:
                self.found_cache[k] = bool(self.matches_cache[k])
            else:
                self.found_cache[k] = self.pattern(name).search(self.data) is not None
        return self.found_cache[k]

    def matches(self, name: str) -> list[tuple[int, int]]:
        k = self.key(name)
        if k not in self.matches_cache:
            pat = self.pattern(name)
            out = []
            pos = 0
            while True:
                m = pat.search(self.data, pos)
                if not m:
                    break
                out.append((m.start(), m.end() - m.start()))
                pos = m.start() + 1              # overlapping matches, like YARA
                if len(out) > 100_000:
                    break
            self.matches_cache[k] = out
            self.found_cache[k] = bool(out)
        return self.matches_cache[k]

    def names(self, sset: Any) -> list[str]:
        if sset[0] == "them":
            return list(self.strings)
        out: list[str] = []
        for item in sset[1]:
            if item.endswith("*"):
                out += [n for n in self.strings if n.startswith(item[:-1])]
            elif item in self.strings:
                out.append(item)
            else:
                raise YaraSyntax(f"unknown string ${item}")
        return out


def _num(v: Any) -> float | int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return v
    raise Undefined()


def _quant_min(q: Any, total: int, ctx: _Ctx) -> int:
    if q[1] == "any":
        return 1
    if q[1] == "all":
        return total
    if q[1] == "none":
        return 0
    n = _num(_eval(q[2], ctx))
    if q[1] == "pct":
        return math.ceil(total * n / 100)
    return int(n)


def _eval(node: Any, ctx: _Ctx) -> Any:
    op = node[0]
    if op == "var":
        if node[1] not in ctx.vars:
            raise Undefined()
        return ctx.vars[node[1]]
    if op == "bool":
        return node[1]
    if op == "num":
        return node[1]
    if op == "lit":
        return node[1]
    if op == "filesize":
        return ctx.filesize
    if op == "ext":
        return ctx.externals.get(node[1], "")
    if op == "rule":
        return ctx.rules(node[1])
    if op == "and":
        return _truth(node[1], ctx) and _truth(node[2], ctx)
    if op == "or":
        return _truth(node[1], ctx) or _truth(node[2], ctx)
    if op == "not":
        return not _truth(node[1], ctx)
    if op == "defined":
        try:
            _eval(node[1], ctx)
            return True
        except Undefined:
            return False
    if op == "found":
        return ctx.found(node[1])
    if op == "at":
        off = _num(_eval(node[2], ctx))
        return any(o == off for o, _ in ctx.matches(node[1]))
    if op == "in":
        lo, hi = _num(_eval(node[2], ctx)), _num(_eval(node[3], ctx))
        return any(lo <= o <= hi for o, _ in ctx.matches(node[1]))
    if op == "count":
        return len(ctx.matches(node[1]))
    if op == "count_in":
        lo, hi = _num(_eval(node[2], ctx)), _num(_eval(node[3], ctx))
        return sum(1 for o, _ in ctx.matches(node[1]) if lo <= o <= hi)
    if op in ("offset", "length"):
        i = int(_num(_eval(node[2], ctx)))
        ms = ctx.matches(node[1])
        if i < 1 or i > len(ms):
            raise Undefined()
        return ms[i - 1][0] if op == "offset" else ms[i - 1][1]
    if op == "read":
        return _read(node[1], int(_num(_eval(node[2], ctx))), ctx)
    if op == "neg":
        return -_num(_eval(node[1], ctx))
    if op == "bitnot":
        return ~int(_num(_eval(node[1], ctx)))
    if op == "bin":
        a, b = _num(_eval(node[2], ctx)), _num(_eval(node[3], ctx))
        o = node[1]
        if o == "+":
            return a + b
        if o == "-":
            return a - b
        if o == "*":
            return a * b
        if o == "\\":
            if b == 0:
                raise Undefined()
            return int(a) // int(b)
        if o == "%":
            if b == 0:
                raise Undefined()
            return int(a) % int(b)
        if o == "|":
            return int(a) | int(b)
        if o == "&":
            return int(a) & int(b)
        if o == "^":
            return int(a) ^ int(b)
        if o == "<<":
            return int(a) << int(b)
        if o == ">>":
            return int(a) >> int(b)
    if op == "cmp":
        a, b = _eval(node[2], ctx), _eval(node[3], ctx)
        if isinstance(a, bytes) or isinstance(b, bytes):
            a, b = _bytes(a), _bytes(b)
        else:
            a, b = _num(a), _num(b)
        o = node[1]
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[o]
    if op == "strop":
        a, b = _bytes(_eval(node[2], ctx)), _bytes(_eval(node[3], ctx))
        o = node[1]
        if o.startswith("i"):
            a, b, o = a.lower(), b.lower(), o[1:]
        return {"contains": b in a, "startswith": a.startswith(b), "endswith": a.endswith(b), "equals": a == b}[o]
    if op == "matches":
        a = _bytes(_eval(node[1], ctx))
        rx = node[2]
        body, flags = rx[1:rx.rindex("/")], rx[rx.rindex("/") + 1:]
        return re.search(body.encode("latin-1"), a, (re.I if "i" in flags else 0) | (re.S if "s" in flags else 0)) is not None
    if op in ("of", "of_in", "of_at"):
        names = ctx.names(node[2])
        need = _quant_min(node[1], len(names), ctx)
        if op == "of":
            hits = sum(1 for n in names if ctx.found(n))
        elif op == "of_in":
            lo, hi = _num(_eval(node[3], ctx)), _num(_eval(node[4], ctx))
            hits = sum(1 for n in names if any(lo <= o <= hi for o, _ in ctx.matches(n)))
        else:
            at = _num(_eval(node[3], ctx))
            hits = sum(1 for n in names if any(o == at for o, _ in ctx.matches(n)))
        return hits == 0 if node[1][1] == "none" else hits >= need
    if op == "for_strings":
        names = ctx.names(node[2])
        need = _quant_min(node[1], len(names), ctx)
        hits = 0
        saved = ctx.anon
        try:
            for n in names:
                ctx.anon = n
                if _truth(node[3], ctx):
                    hits += 1
        finally:
            ctx.anon = saved
        return hits == 0 if node[1][1] == "none" else hits >= need
    if op == "for_ints":
        it = node[3]
        if it[0] == "range":
            lo, hi = int(_num(_eval(it[1], ctx))), int(_num(_eval(it[2], ctx)))
            if hi - lo > 100_000:
                raise Undefined()
            values = range(lo, hi + 1)
        else:
            values = [_eval(v, ctx) for v in it[1]]
        total = len(values)
        need = _quant_min(node[1], total, ctx)
        hits = 0
        saved = ctx.vars.get(node[2])
        try:
            for v in values:
                ctx.vars[node[2]] = v
                if _truth(node[4], ctx):
                    hits += 1
                    if node[1][1] != "none" and hits >= need:
                        break
        finally:
            if saved is None:
                ctx.vars.pop(node[2], None)
            else:
                ctx.vars[node[2]] = saved
        return hits == 0 if node[1][1] == "none" else hits >= need
    raise YaraSyntax(f"cannot evaluate {op}")


def _truth(node: Any, ctx: _Ctx) -> bool:
    try:
        v = _eval(node, ctx)
    except Undefined:
        return False
    if isinstance(v, bytes):
        return bool(v)
    return bool(v)


def _bytes(v: Any) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return v.encode("latin-1", "replace")
    raise Undefined()


_READ = {"uint8": ("<B", 1), "uint16": ("<H", 2), "uint32": ("<I", 4), "int8": ("<b", 1), "int16": ("<h", 2),
         "int32": ("<i", 4), "uint16be": (">H", 2), "uint32be": (">I", 4), "int16be": (">h", 2), "int32be": (">i", 4),
         "uint8be": (">B", 1), "int8be": (">b", 1)}


def _read(fn: str, off: int, ctx: _Ctx) -> int:
    fmt, n = _READ[fn]
    if off < 0 or off + n > len(ctx.data):
        raise Undefined()
    return struct.unpack(fmt, ctx.data[off:off + n])[0]


# `rule` nodes in the AST refer to variables inside for-loops too: resolve those first.
def _bind_vars(node: Any, names: set[str]) -> Any:
    if not isinstance(node, tuple):
        return node
    if node[0] == "rule" and node[1] in names:
        return ("var", node[1])
    if node[0] == "for_ints":
        inner = names | {node[2]}
        return ("for_ints", _bind_vars(node[1], names), node[2], _bind_vars(node[3], names), _bind_vars(node[4], inner))
    return tuple(_bind_vars(x, names) if isinstance(x, tuple) else
                 ([_bind_vars(y, names) for y in x] if isinstance(x, list) else x) for x in node)


# ================================================================ detection object
_CACHE: dict[str, "YaraDetection"] = {}
_CACHE_MAX = 20000


def compile_detection(spec: dict[str, Any]) -> "YaraDetection":
    """YaraDetection for a `where: {yara: ...}` spec, cached by content (compiling is regex-bound)."""
    import json
    deps = spec.get("dependencies") or {}
    # the dependency map can be a whole source (thousands of rules): key on its identity and size, not its content
    key = json.dumps([spec.get("name", ""), spec["condition"], spec["strings"]], sort_keys=True, default=str) \
        + f"|{id(deps)}:{len(deps)}"
    det = _CACHE.get(key)
    if det is None:
        det = YaraDetection(spec["strings"], spec["condition"], spec.get("dependencies"), spec.get("name", ""))
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[key] = det
    return det


class YaraDetection:
    """A compiled YARA rule that `matches(event)` over the event's file content."""

    def __init__(self, strings: list[dict[str, Any]] | list[YString], condition: str,
                 dependencies: dict[str, dict[str, Any]] | None = None, name: str = "") -> None:
        self.name = name
        ys = [s if isinstance(s, YString) else YString.from_dict(s) for s in strings]
        self.strings = {s.id: compile_string(s) for s in ys}
        self.ast = _bind_vars(parse_condition(condition), set())
        self._dep_specs = dependencies or {}
        self._deps: dict[str, YaraDetection] = {}
        self.referenced: list[str] = []
        self._check_refs(self.ast, [name])

    def _check_refs(self, node: Any, chain: list[str]) -> None:
        """Compile referenced rules now (so an unsupported dependency is found at compile time)."""
        if not isinstance(node, tuple):
            return
        if node[0] == "rule":
            ref = node[1]
            if ref in chain:
                raise YaraUnsupported(f"circular reference to rule {ref}")
            if ref not in self._dep_specs:
                raise YaraUnsupported(f"reference to rule {ref} not available")
            if ref not in self._deps:
                spec = self._dep_specs[ref]
                self._deps[ref] = compile_detection({"name": ref, "strings": spec["strings"], "condition": spec["condition"],
                                                     "dependencies": self._dep_specs})
            if ref not in self.referenced:
                self.referenced.append(ref)
            return
        for x in node:
            if isinstance(x, tuple):
                self._check_refs(x, chain)
            elif isinstance(x, list):
                for y in x:
                    self._check_refs(y, chain)

    def dependency_specs(self) -> dict[str, dict[str, Any]]:
        """Specs of every rule this one depends on, transitively (to embed in a corpus file)."""
        out: dict[str, dict[str, Any]] = {}
        todo = list(self.referenced)
        while todo:
            n = todo.pop()
            if n in out:
                continue
            out[n] = self._dep_specs[n]
            todo += self._deps[n].referenced if n in self._deps else []
        return out

    @staticmethod
    def content_of(event: Event) -> bytes | None:
        f = event.fields
        c = f.get("content")
        if isinstance(c, (bytes, bytearray)):
            return bytes(c)
        if isinstance(c, str):
            return c.encode("latin-1", "replace")
        b64 = f.get("content_b64")
        if isinstance(b64, str):
            try:
                return base64.b64decode(b64)
            except ValueError:
                return None
        return None

    def matches_bytes(self, data: bytes, filesize: int | None = None, externals: dict[str, Any] | None = None) -> bool:
        size = len(data) if filesize is None else int(filesize)
        memo: dict[str, bool] = {}

        def rule_ref(name: str) -> bool:
            if name not in memo:
                memo[name] = self._deps[name].matches_bytes(data, size, externals) if name in self._deps else False
            return memo[name]

        ctx = _Ctx(data, size, self.strings, externals or {}, rule_ref)
        return _truth(self.ast, ctx)

    def matches(self, event: Event) -> bool:
        data = self.content_of(event)
        if data is None:
            return False
        f = event.fields
        size = f.get("size") or f.get("filesize")
        externals = {k: f[k] for k in EXTERNALS if k in f}
        if "filename" not in externals and f.get("TargetFilename"):
            externals["filename"] = str(f["TargetFilename"]).replace("\\", "/").rsplit("/", 1)[-1]
        return self.matches_bytes(data, size, externals)
