"""Phase B, YARA: parser, string compilation, condition evaluation, importer, differential vs yara-python."""
import base64
import re

import pytest

from chain import Engine, Event, load_rule
from chain.importers.yara import yara_import
from chain.yara import (YaraDetection, YaraUnsupported, YString, compile_string, hex_regex, parse_condition,
                        parse_file, text_regex, unescape_text)

SAMPLE = r'''
import "pe"

/* a block comment with a rule-looking word: rule not_a_rule { } */
private rule Is_PE {
    condition:
        uint16(0) == 0x5a4d
}

rule Demo_Text : apt windows {
    meta:
        description = "demo"
        score = 80
        enabled = true
    strings:
        $a = "evil" nocase        // trailing comment
        $b = "Mimikatz" wide ascii fullword
        $c = { 4D 5A ?? 00 [2-4] (AA | BB) 9? }
        $re = /pass(word)?=[a-z]{3,8}/i
        $ = "anon1"
        $ = "anon2"
    condition:
        Is_PE and (2 of ($a, $b, $re) or all of ($c) or #a > 2) and filesize < 10KB
}

rule Needs_Module {
    strings:
        $x = "x"
    condition:
        $x and pe.imphash() == "abc"
}
'''


# ---------------------------------------------------------------- parsing
def test_parse_file_handles_comments_braces_meta_and_anonymous_strings():
    rules, imports = parse_file(SAMPLE)
    assert imports == ["pe"] and [r.name for r in rules] == ["Is_PE", "Demo_Text", "Needs_Module"]
    r = rules[1]
    assert r.tags == ["apt", "windows"] and r.meta == {"description": "demo", "score": 80, "enabled": True}
    assert [s.id for s in r.strings] == ["a", "b", "c", "re", "__anon1", "__anon2"]
    assert r.strings[0].modifiers == ["nocase"] and r.strings[1].modifiers == ["wide", "ascii", "fullword"]
    assert r.strings[2].kind == "hex" and r.strings[3].kind == "regex" and r.strings[3].regex_flags == "i"
    assert r.condition.startswith("Is_PE and (2 of ($a, $b, $re)")
    assert rules[0].private and "private rule Is_PE" in rules[0].source and r.source.rstrip().endswith("}")


def test_regex_literal_braces_do_not_break_brace_matching():
    rules, _ = parse_file('rule R { strings: $r = /a{2,3}b/ condition: $r }\nrule S { condition: true }')
    assert [r.name for r in rules] == ["R", "S"]


# ---------------------------------------------------------------- strings
def test_text_string_variants():
    assert unescape_text(r'a\"b\\c\x41\n') == b'a"b\\cA\n'
    plain = compile_string(YString("a", "text", "Evil"))
    assert plain.search(b"xxEvilxx") and not plain.search(b"xxevilxx")
    nocase = compile_string(YString("a", "text", "Evil", ["nocase"]))
    assert nocase.search(b"xxEVILxx")
    wide = compile_string(YString("a", "text", "ab", ["wide"]))
    assert wide.search(b"a\x00b\x00") and not wide.search(b"ab")
    both = compile_string(YString("a", "text", "ab", ["wide", "ascii"]))
    assert both.search(b"ab") and both.search(b"a\x00b\x00")
    full = compile_string(YString("a", "text", "cmd", ["fullword"]))
    assert full.search(b"run cmd now") and not full.search(b"runcmd.exe")
    xor = compile_string(YString("a", "text", "key", ["xor"]))
    assert xor.search(bytes(c ^ 0x41 for c in b"key")) and xor.search(b"key")
    xor_r = compile_string(YString("a", "text", "key", ["xor(0x10-0x12)"]))
    assert xor_r.search(bytes(c ^ 0x11 for c in b"key")) and not xor_r.search(bytes(c ^ 0x41 for c in b"key"))
    b64 = compile_string(YString("a", "text", "powershell", ["base64"]))
    for prefix in (b"", b"x", b"xy"):
        assert b64.search(base64.b64encode(prefix + b"powershell -enc")), prefix
    with pytest.raises(YaraUnsupported):
        text_regex(YString("a", "text", "k" * 400, ["xor"]))


def test_hex_strings():
    pat = re.compile(hex_regex("4D 5A ?? 00 [2-4] (AA | BB) 9?"), re.S)
    assert pat.search(b"MZ\x07\x00\x01\x02\xaa\x91")
    assert pat.search(b"MZ\x07\x00\x01\x02\x03\x04\xbb\x9f")
    assert not pat.search(b"MZ\x07\x00\x01\xaa\x91")           # jump below minimum
    assert not pat.search(b"MZ\x07\x00\x01\x02\xaa\x81")       # nibble wildcard: high nibble must be 9
    assert re.compile(hex_regex("41 [-] 42"), re.S).search(b"A....B")
    assert re.compile(hex_regex("41 [3] 42"), re.S).search(b"AxyzB")
    with pytest.raises(YaraUnsupported):
        hex_regex("~41")


def test_regex_strings_and_unsupported_wide_regex():
    rx = compile_string(YString("r", "regex", "pass(word)?=[a-z]{3,8}", [], "i"))
    assert rx.search(b"PASSWORD=secret")
    with pytest.raises(YaraUnsupported):
        compile_string(YString("r", "regex", "a", ["wide"]))


# ---------------------------------------------------------------- conditions
def det(cond: str, strings: dict[str, str] | None = None, deps=None) -> YaraDetection:
    ss = [YString(k, "text", v) for k, v in (strings or {}).items()]
    return YaraDetection(ss, cond, deps, "t")


def test_boolean_of_and_counts():
    d = det("2 of them", {"a": "aa", "b": "bb", "c": "cc"})
    assert d.matches_bytes(b"aa bb") and not d.matches_bytes(b"aa")
    assert det("all of ($a*)", {"a1": "x", "a2": "y", "b": "z"}).matches_bytes(b"xy")
    assert not det("all of ($a*)", {"a1": "x", "a2": "y", "b": "z"}).matches_bytes(b"x")
    assert det("none of them", {"a": "x"}).matches_bytes(b"q") and not det("none of them", {"a": "x"}).matches_bytes(b"x")
    assert det("50% of them", {"a": "x", "b": "y", "c": "z", "d": "w"}).matches_bytes(b"xy")
    assert det("#a > 2 and #a < 5", {"a": "x"}).matches_bytes(b"xxx") and not det("#a > 2", {"a": "x"}).matches_bytes(b"xx")
    assert det("$a and not $b", {"a": "x", "b": "y"}).matches_bytes(b"x")
    assert det("(1 of ($a, $b)) and true", {"a": "x", "b": "y"}).matches_bytes(b"y")


def test_offsets_ranges_and_lengths():
    d = det("$a at 0", {"a": "MZ"})
    assert d.matches_bytes(b"MZ..") and not d.matches_bytes(b".MZ.")
    assert det("$a in (2..4)", {"a": "x"}).matches_bytes(b"..x") and not det("$a in (2..4)", {"a": "x"}).matches_bytes(b"x....")
    assert det("@a[2] == 3", {"a": "x"}).matches_bytes(b"x..x")
    assert det("!a == 3", {"a": "abc"}).matches_bytes(b"abc")
    assert not det("@a[5] == 0", {"a": "x"}).matches_bytes(b"x")                 # undefined -> false
    assert det("#a in (0..2) == 1", {"a": "x"}).matches_bytes(b"x.....x")
    assert det("$a at (filesize - 2)", {"a": "ab"}).matches_bytes(b"xxab")
    assert det("any of them in (0..1)", {"a": "x", "b": "y"}).matches_bytes(b"y..") and not det("all of them in (0..1)", {"a": "x", "b": "y"}).matches_bytes(b"y..x")


def test_integers_filesize_and_arithmetic():
    d = det("uint16(0) == 0x5a4d and uint32be(4) == 0x01020304 and filesize == 8 and (filesize * 2) \\ 4 == 4")
    assert d.matches_bytes(b"MZ\x00\x00\x01\x02\x03\x04")
    assert not det("uint32(100) == 1").matches_bytes(b"short")                   # read out of range -> undefined
    assert det("filesize < 1KB and filesize > 2").matches_bytes(b"xxxx")
    assert det("int8(0) == -1").matches_bytes(b"\xff")
    assert det("uint8(0) & 0x0f == 0x0a").matches_bytes(b"\x1a")


def test_for_loops_and_anonymous_strings():
    d = det("for any of them : ($ at 0)", {"a": "x", "b": "y"})
    assert d.matches_bytes(b"y...") and not d.matches_bytes(b"..y")
    assert det("for all of ($a*) : (# > 1)", {"a1": "x", "a2": "y"}).matches_bytes(b"xxyy")
    assert not det("for all of ($a*) : (# > 1)", {"a1": "x", "a2": "y"}).matches_bytes(b"xxy")
    d = det("for any i in (1..#a) : (@a[i] == 4)", {"a": "x"})
    assert d.matches_bytes(b"x...x") and not d.matches_bytes(b"x.x")
    assert det("for all i in (0, 2) : (uint8(i) == 0x41)").matches_bytes(b"A.A")
    anon = YaraDetection([YString("__anon1", "text", "p"), YString("__anon2", "text", "q")], "all of them")
    assert anon.matches_bytes(b"pq") and not anon.matches_bytes(b"p")


def test_rule_references_externals_and_string_ops():
    deps = {"Is_PE": {"strings": [], "condition": "uint16(0) == 0x5a4d"}}
    d = det("Is_PE and $a", {"a": "x"}, deps)
    assert d.matches_bytes(b"MZx") and not d.matches_bytes(b"ZZx")
    assert d.referenced == ["Is_PE"] and d.dependency_specs() == deps
    with pytest.raises(YaraUnsupported, match="not available"):
        det("Missing and $a", {"a": "x"})
    ext = det('filename contains "evil" and extension iequals "EXE"')
    assert ext.matches_bytes(b"", externals={"filename": "evil.exe", "extension": "exe"})
    assert not ext.matches_bytes(b"", externals={"filename": "good.exe", "extension": "exe"})
    assert det('filename matches /^ev.l/i').matches_bytes(b"", externals={"filename": "EVIL"})
    assert not det('filename contains "x"').matches_bytes(b"")                     # missing external = ""


def test_unsupported_constructs_are_reported_not_guessed():
    for cond in ("pe.imphash() == \"a\"", "math.entropy(0, filesize) > 7", "entrypoint == 0", "pe.signatures[0].issuer contains \"x\""):
        with pytest.raises(YaraUnsupported):
            det(cond, {"a": "x"})
    with pytest.raises(Exception):
        parse_condition("$a and and $b")


# ---------------------------------------------------------------- events + engine
def test_detection_reads_event_content_in_three_forms():
    d = det("$a at 0 and filesize == 4", {"a": "ab"})
    assert d.matches(Event(type="file.scan", fields={"content": "ab\x00\xff"}))                # latin-1 str
    assert d.matches(Event(type="file.scan", fields={"content": b"ab\x00\xff"}))
    assert d.matches(Event(type="file.scan", fields={"content_b64": base64.b64encode(b"ab\x00\xff").decode()}))
    assert not d.matches(Event(type="file.scan", fields={}))
    sized = det("filesize > 1000", {"a": "x"})
    assert sized.matches(Event(type="file.scan", fields={"content": "head only", "size": 5000}))   # declared size wins


def test_importer_native_and_delegated_through_engine():
    imps = yara_import(SAMPLE)
    by = {i.name: i for i in imps}
    assert not by["Demo_Text"].delegated and by["Needs_Module"].delegated and not by["Is_PE"].delegated
    assert "dependencies" in by["Demo_Text"].rule["sequence"][0]["where"]["yara"]
    assert "Is_PE" in by["Demo_Text"].rule["sequence"][0]["where"]["yara"]["dependencies"]
    assert by["Demo_Text"].rule["severity"] == "critical" and by["Demo_Text"].meta["meta"]["score"] == 80
    assert 'import "pe"' in by["Needs_Module"].source
    eng = Engine([load_rule(i.rule) for i in imps])
    content = b"MZ" + b"\x00" * 10 + b"evil Mimikatz password=secret"
    v = eng.evaluate(Event(type="file.scan", fields={"content": content.decode("latin-1")}))
    assert {h.rule_id for h in v.hits} == {"yara_Demo_Text", "yara_Is_PE"}
    assert eng.evaluate(Event(type="file.scan", fields={"yara_matches": ["Needs_Module"]})).hits


# ---------------------------------------------------------------- differential vs the reference engine
yara = pytest.importorskip("yara")

DIFF_RULES = r'''
rule T1 { strings: $a = "evil" nocase $b = "Mimikatz" wide ascii fullword condition: 2 of them }
rule T2 { strings: $h = { 4D 5A ?? 00 [2-4] (AA | BB) 9? } condition: $h at 0 }
rule T3 { strings: $r = /pass(word)?=[a-z]{3,8}/i condition: $r and #r == 1 }
rule T4 { strings: $x = "key" xor condition: $x }
rule T5 { strings: $b = "powershell" base64 condition: $b }
rule T6 { strings: $a = "x" condition: for any i in (1..#a) : (@a[i] == 4) }
rule T7 { strings: $a = "ab" condition: uint16(0) == 0x5a4d and filesize < 100 and $a in (2..5) }
rule T8 { strings: $ = "anon1" $ = "anon2" condition: all of them }
rule T9 { strings: $a = "q" condition: none of them }
rule T10 { strings: $s1 = "A" $s2 = "B" $s3 = "C" condition: 50% of ($s*) }
'''
SAMPLES = [
    b"MZ\x07\x00\x01\x02\xaa\x91 evil M\x00i\x00m\x00i\x00k\x00a\x00t\x00z\x00 PASSWORD=secret",
    b"MZ\x07\x00\x01\x02\x03\x04\xbb\x9f ab",
    b"nothing here", b"", b"x...x", b"anon1 anon2", b"A B", b"A",
    bytes(c ^ 0x41 for c in b"key"), base64.b64encode(b"xpowershell -enc"),
    b"MZab evil",
]


def test_differential_against_yara_python():
    native = yara.compile(source=DIFF_RULES)
    mine = {i.name: YaraDetection(i.rule["sequence"][0]["where"]["yara"]["strings"],
                                  i.rule["sequence"][0]["where"]["yara"]["condition"])
            for i in yara_import(DIFF_RULES)}
    assert len(mine) == 10
    disagreements = []
    for data in SAMPLES:
        ref = {m.rule for m in native.match(data=data)}
        for name, d in mine.items():
            if d.matches_bytes(data) != (name in ref):
                disagreements.append((name, data[:30]))
    assert disagreements == []
