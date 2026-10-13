"""Phase B, Sigma: remaining modifiers, legacy aggregations, correlation rules, composite group_by."""
import base64
from pathlib import Path

import pytest

from chain import Engine, Event, load_rule
from chain.corpus.pipeline import sync_source
from chain.corpus.sources import add_source
from chain.importers.sigma import SigmaUnsupported, parse_timespan, sigma_import, sigma_import_correlation


def rule(sel: str, extra: str = "", category: str = "process_creation", **kw) -> Engine:
    text = f"title: t\nlogsource: {{category: {category}}}\ndetection:\n  s: {sel}\n{extra}  condition: s\n"
    return Engine([load_rule(sigma_import(text, **kw).rule)])


def ev(**fields) -> Event:
    return Event(type="process.start", **({"fields": fields} if fields else {}))


# ---------------------------------------------------------------- modifiers
def test_base64offset_with_utf16le_matches_all_three_alignments():
    eng = rule("{CommandLine|base64offset|contains: '::FromBase64String'}")
    for prefix in ("", "x", "xy"):                       # shifts the alignment of the encoded value
        blob = base64.b64encode((prefix + "::FromBase64String(").encode()).decode()
        assert eng.evaluate(ev(CommandLine=f"powershell -enc {blob}")).hits, prefix
    assert not eng.evaluate(ev(CommandLine="powershell -enc QUJD")).hits
    wide = rule("{CommandLine|utf16le|base64offset|contains: 'Invoke-Mimikatz'}")
    blob = base64.b64encode("Invoke-Mimikatz -DumpCreds".encode("utf-16-le")).decode()
    assert wide.evaluate(ev(CommandLine=f"-enc {blob}")).hits
    assert not rule("{CommandLine|base64offset|contains: 'Invoke-Mimikatz'}").evaluate(ev(CommandLine=f"-enc {blob}")).hits


def test_base64_with_wide_and_plain():
    eng = rule("{CommandLine|wide|base64|contains: 'cmd'}")
    assert eng.evaluate(ev(CommandLine=base64.b64encode("cmd".encode("utf-16-le")).decode())).hits
    plain = rule("{CommandLine|base64: 'cmd'}")
    assert plain.evaluate(ev(CommandLine=base64.b64encode(b"cmd").decode())).hits


def test_numeric_comparisons():
    eng = rule("{Port|gte: 1024, Port|lt: 49152}")
    assert eng.evaluate(ev(Port=8080)).hits and eng.evaluate(ev(Port="1024")).hits
    assert not eng.evaluate(ev(Port=80)).hits and not eng.evaluate(ev(Port=60000)).hits
    assert not eng.evaluate(ev(Port="n/a")).hits


def test_fieldref_compares_two_fields():
    eng = rule("{TargetFilename|fieldref: Image}")
    assert eng.evaluate(ev(TargetFilename=r"C:\x\a.exe", Image=r"C:\x\a.exe")).hits
    assert not eng.evaluate(ev(TargetFilename=r"C:\x\a.exe", Image=r"C:\x\b.exe")).hits
    assert not eng.evaluate(ev(TargetFilename=r"C:\x\a.exe")).hits
    assert not eng.evaluate(ev()).hits                            # both fields missing is not a match
    ends = rule("{User|fieldref|endswith: ParentUser}")
    assert ends.evaluate(ev(User=r"CORP\bob", ParentUser="bob")).hits


def test_regex_flags():
    assert rule("{CommandLine|re|i: '^c:\\\\windows\\\\x$'}").evaluate(ev(CommandLine=r"C:\Windows\X")).hits
    assert not rule("{CommandLine|re: '^c:\\\\windows\\\\x$'}").evaluate(ev(CommandLine=r"C:\Windows\X")).hits
    assert rule("{ScriptBlockText|re|m: '^Invoke'}").evaluate(ev(ScriptBlockText="x\nInvoke-Y")).hits
    assert rule("{ScriptBlockText|re|s: 'a.b'}").evaluate(ev(ScriptBlockText="a\nb")).hits


def test_expand_placeholders_resolved_and_unresolved():
    text = "title: t\nlogsource: {category: process_creation}\ndetection:\n  s: {User|expand: '%admins%'}\n  condition: s\n"
    imp = sigma_import(text, placeholders={"admins": ["alice", "bob"]})
    assert imp.notes == [] and imp.rule["sequence"][0]["where"]["sigma"]["detection"]["s"] == {"User": ["alice", "bob"]}
    eng = Engine([load_rule(imp.rule)])
    assert eng.evaluate(ev(User="bob")).hits and not eng.evaluate(ev(User="eve")).hits
    unresolved = sigma_import(text)
    assert any("%admins%" in n for n in unresolved.notes)
    assert Engine([load_rule(unresolved.rule)]).evaluate(ev(User="anyone")).hits     # wildcard
    sub = sigma_import("title: t\nlogsource: {category: process_creation}\ndetection:\n"
                       "  s: {CommandLine|contains|expand: '%userdomain%\\\\admin'}\n  condition: s\n",
                       placeholders={"userdomain": ["CORP"]})
    assert sub.rule["sequence"][0]["where"]["sigma"]["detection"]["s"] == {"CommandLine|contains": "CORP\\\\admin"}


# ---------------------------------------------------------------- legacy aggregations
def test_parse_timespan():
    assert parse_timespan("30s") == 30 and parse_timespan("5m") == 300 and parse_timespan("24h") == 86400
    assert parse_timespan("7d") == 7 * 86400
    with pytest.raises(SigmaUnsupported):
        parse_timespan("soon")


def test_count_by_converts_to_count_step_and_fires_at_threshold():
    text = ("title: txt\nlogsource: {category: dns}\ndetection:\n  selection: {record_type: TXT}\n"
            "  timeframe: 1m\n  condition: selection | count() by src_ip > 50\n")
    imp = sigma_import(text)
    step = imp.rule["sequence"][0]
    assert step["count"] == {"min": 51, "within": 60.0} and imp.rule["group_by"] == "fields.src_ip"
    assert "condition" in step["where"]["sigma"]["detection"] and "|" not in step["where"]["sigma"]["detection"]["condition"]
    assert imp.notes == []
    eng = Engine([load_rule(imp.rule)])
    fired = []
    for i in range(51):
        fired.append(bool(eng.evaluate(Event(type="net.dns", ts=i, fields={"record_type": "TXT", "src_ip": "10.0.0.1"})).hits))
    assert fired[:50] == [False] * 50 and fired[50]
    # a different source ip has its own count; a non-TXT record doesn't count
    assert not eng.evaluate(Event(type="net.dns", ts=52, fields={"record_type": "TXT", "src_ip": "10.0.0.2"})).hits
    slow = Engine([load_rule(imp.rule)])
    for i in range(51):
        slow.evaluate(Event(type="net.dns", ts=i * 10, fields={"record_type": "TXT", "src_ip": "10.0.0.1"}))
    assert not any(slow.evaluate(Event(type="net.dns", ts=600, fields={"record_type": "TXT", "src_ip": "10.0.0.1"})).hits for _ in [0])


def test_count_distinct_field_and_filters():
    text = ("title: k\nlogsource: {product: windows, service: security}\ndetection:\n"
            "  selection: {EventID: 4768, Status: '0x12'}\n  filter_computer: {TargetUserName|endswith: '$'}\n"
            "  timeframe: 24h\n  condition: selection and not filter_computer | count(TargetUserName) by IpAddress > 10\n")
    imp = sigma_import(text)
    assert imp.rule["sequence"][0]["count"] == {"min": 11, "within": 86400.0, "distinct": "fields.TargetUserName"}
    eng = Engine([load_rule(imp.rule)])
    base = {"EventID": 4768, "Status": "0x12", "IpAddress": "203.0.113.5"}
    for i in range(11):   # same user 11 times: only one distinct value
        assert not eng.evaluate(Event(type="log.windows.security", ts=i, fields={**base, "TargetUserName": "alice"})).hits
    hits = [bool(eng.evaluate(Event(type="log.windows.security", ts=20 + i, fields={**base, "TargetUserName": f"u{i}"})).hits)
            for i in range(10)]
    assert hits[-1] and not any(hits[:-1])
    # computer accounts are filtered before counting
    fresh = Engine([load_rule(imp.rule)])
    for i in range(12):
        assert not fresh.evaluate(Event(type="log.windows.security", ts=i, fields={**base, "TargetUserName": f"WS{i}$"})).hits


def test_global_count_and_unsupported_aggregations():
    imp = sigma_import("title: g\nlogsource: {category: dns}\ndetection:\n  s: {a: 1}\n  timeframe: 1m\n  condition: s | count() > 5\n")
    assert imp.rule["group_by"] is None and imp.rule["sequence"][0]["count"]["min"] == 6
    eng = Engine([load_rule(imp.rule)])
    fired = [bool(eng.evaluate(Event(type="net.dns", ts=i, host=f"h{i}", fields={"a": 1})).hits) for i in range(6)]
    assert fired == [False] * 5 + [True]
    no_tf = sigma_import("title: g\nlogsource: {category: dns}\ndetection:\n  s: {a: 1}\n  condition: s | count() >= 3\n")
    assert no_tf.rule["sequence"][0]["count"] == {"min": 3, "within": 86400.0} and any("24h" in n for n in no_tf.notes)
    for cond in ("s | sum(bytes) by src_ip > 300000", "s | count() by TaskName < 5", "s | near s2", "s | count() > 0"):
        with pytest.raises(SigmaUnsupported):
            sigma_import(f"title: g\nlogsource: {{category: dns}}\ndetection:\n  s: {{a: 1}}\n  s2: {{b: 1}}\n  timeframe: 1m\n  condition: {cond}\n")


# ---------------------------------------------------------------- correlation rules
BASE_FAIL = """
title: Failed logon
id: aaaaaaaa-0000-0000-0000-000000000001
name: failed_logon
logsource: {product: windows, service: security}
detection:
  s: {EventID: 4625}
  condition: s
"""
BASE_SUCCESS = """
title: Successful logon
id: aaaaaaaa-0000-0000-0000-000000000002
name: successful_logon
logsource: {product: windows, service: security}
detection:
  s: {EventID: 4624}
  condition: s
"""
CORR_COUNT = """
title: Many failed logons from one source
id: bbbbbbbb-0000-0000-0000-000000000001
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [IpAddress]
  timespan: 5m
  condition: {gte: 5}
level: high
"""
CORR_VALUE = """
title: Password spraying
id: bbbbbbbb-0000-0000-0000-000000000002
correlation:
  type: value_count
  rules: [failed_logon]
  group-by: [IpAddress]
  timespan: 10m
  field: TargetUserName
  condition: {gte: 3}
"""
CORR_TEMPORAL = """
title: Failed then successful logon
id: bbbbbbbb-0000-0000-0000-000000000003
correlation:
  type: temporal_ordered
  rules: [failed_logon, successful_logon]
  group-by: [IpAddress, TargetUserName]
  timespan: 2m
level: critical
"""


def _lookup():
    rules = {imp.meta["name"]: imp.rule for imp in (sigma_import(BASE_FAIL), sigma_import(BASE_SUCCESS))}
    return rules.get


def test_event_count_correlation():
    imp = sigma_import_correlation(__import__("yaml").safe_load(CORR_COUNT), _lookup())
    r = imp.rule
    assert r["group_by"] == ["fields.IpAddress"] and r["sequence"][0]["count"] == {"min": 5, "within": 300.0}
    assert r["sequence"][0]["name"] == "failed_logon" and imp.notes == [] and r["severity"] == "high"
    eng = Engine([load_rule(r)])
    fired = [bool(eng.evaluate(Event(type="log.windows.security", ts=i, fields={"EventID": 4625, "IpAddress": "1.2.3.4"})).hits)
             for i in range(5)]
    assert fired == [False] * 4 + [True]


def test_value_count_correlation():
    r = sigma_import_correlation(__import__("yaml").safe_load(CORR_VALUE), _lookup()).rule
    assert r["sequence"][0]["count"] == {"min": 3, "within": 600.0, "distinct": "fields.TargetUserName"}


def test_temporal_ordered_correlation_with_composite_group():
    imp = sigma_import_correlation(__import__("yaml").safe_load(CORR_TEMPORAL), _lookup())
    r = imp.rule
    assert [s["name"] for s in r["sequence"]] == ["failed_logon", "successful_logon"]
    assert r["group_by"] == ["fields.IpAddress", "fields.TargetUserName"] and r["window"] == {"seconds": 120.0}
    eng = Engine([load_rule(r)])
    f = {"EventID": 4625, "IpAddress": "1.2.3.4", "TargetUserName": "bob"}
    s = {"EventID": 4624, "IpAddress": "1.2.3.4", "TargetUserName": "bob"}
    eng.evaluate(Event(type="log.windows.security", ts=0, fields=f))
    other = eng.evaluate(Event(type="log.windows.security", ts=1, fields={**s, "TargetUserName": "alice"}))
    assert not other.hits                                          # same ip, different user: different group
    assert eng.evaluate(Event(type="log.windows.security", ts=2, fields=s)).hits
    late = Engine([load_rule(r)])
    late.evaluate(Event(type="log.windows.security", ts=0, fields=f))
    assert not late.evaluate(Event(type="log.windows.security", ts=500, fields=s)).hits   # outside timespan


def test_unordered_temporal_is_lossy_and_errors_are_clear():
    doc = __import__("yaml").safe_load(CORR_TEMPORAL.replace("temporal_ordered", "temporal"))
    imp = sigma_import_correlation(doc, _lookup())
    assert any("unordered" in n for n in imp.notes)
    with pytest.raises(SigmaUnsupported, match="unknown rule"):
        sigma_import_correlation(__import__("yaml").safe_load(CORR_COUNT.replace("failed_logon", "nope")), _lookup())
    with pytest.raises(SigmaUnsupported, match="only gt / gte"):
        sigma_import_correlation(__import__("yaml").safe_load(CORR_COUNT.replace("gte: 5", "lt: 5")), _lookup())


def test_pipeline_resolves_correlations_in_second_pass(tmp_path):
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    (repo / "rules/zz_corr.yml").write_text(CORR_TEMPORAL)       # sorts after its base rules? no: before 'fail'... keep both orders honest
    (repo / "rules/aa_corr_count.yml").write_text(CORR_COUNT)   # sorts before its base rule
    (repo / "rules/fail.yml").write_text(BASE_FAIL)
    (repo / "rules/success.yml").write_text(BASE_SUCCESS)
    src = add_source(str(repo), "corr", tmp_path / "sources", paths=["rules"])
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache")
    assert rep.failed == 0 and rep.imported == 4
    by = {i.path: i for i in rep.items}
    assert by["rules/aa_corr_count.yml"].fidelity == "exact" and by["rules/zz_corr.yml"].fidelity == "exact"
    eng = Engine.from_paths(tmp_path / "corpus/corr")
    assert len(eng.rules) == 4
    corr = [r for r in eng.rules if r.id == "sigma_bbbbbbbb_0000_0000_0000_000000000003"][0]
    assert corr.rule.origin.upstream_name is None and "sigma:correlation" in corr.rule.tags
    assert corr.group_fields == ("fields.IpAddress", "fields.TargetUserName")


# ---------------------------------------------------------------- composite / global group_by in the engine
def test_composite_and_global_group_by():
    comp = load_rule({"id": "c", "group_by": ["host", "user"], "sequence": [{"name": "a", "event": "x.a"}, {"name": "b", "event": "x.b"}]})
    eng = Engine([comp])
    eng.evaluate(Event(type="x.a", host="h", user="u"))
    assert not eng.evaluate(Event(type="x.b", host="h", user="v")).hits
    assert eng.evaluate(Event(type="x.b", host="h", user="u")).hits
    glob = load_rule({"id": "g", "group_by": None, "sequence": [{"name": "a", "event": "x.a"}, {"name": "b", "event": "x.b"}]})
    eng = Engine([glob])
    eng.evaluate(Event(type="x.a", host="h1"))
    assert eng.evaluate(Event(type="x.b", host="h2")).hits


def test_corpus_fixture_still_syncs(tmp_path):
    # guards the refactor of the sync loop: the Phase A fixture results are unchanged
    from tests.test_corpus import make_repo
    repo = make_repo(tmp_path)
    src = add_source(str(repo), "fx", tmp_path / "sources", paths=["rules", "yara"])
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache")
    assert (rep.imported, rep.failed, rep.skipped, rep.flagged) == (6, 2, 1, 2)
    assert Path(tmp_path / "corpus/fx/index.json").exists()
