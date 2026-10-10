"""Phase A: source manifests, fetch, sync pipeline, fidelity labels and safety checks."""
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from chain import Engine, Event
from chain.cli import main
from chain.corpus.pipeline import sync_source
from chain.corpus.safety import check_regex, check_rule
from chain.corpus.sources import add_source, fetch, list_sources, load_source
from chain.importers.sigma import SigmaUnsupported, sigma_import
from chain.importers.yara import yara_import
from chain.rules import load_rule

SIGMA_CLEAN = """
title: Encoded PowerShell
id: 11111111-1111-1111-1111-111111111111
status: test
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: ' -enc '
  condition: selection
falsepositives: [Admin scripts]
"""
SIGMA_LOSSY = """
title: Private range
id: 22222222-2222-2222-2222-222222222222
status: stable
logsource: {category: network_connection, product: windows}
detection:
  selection: {CommandLine|base64offset|contains: cmd}
  condition: selection
"""
SIGMA_DEPRECATED = """
title: Old
id: 33333333-3333-3333-3333-333333333333
status: deprecated
logsource: {category: process_creation}
detection:
  selection: {Image|endswith: '\\old.exe'}
  condition: selection
"""
SIGMA_AGG = """
title: Many failures
id: 44444444-4444-4444-4444-444444444444
logsource: {product: windows, service: security}
detection:
  selection: {EventID: 4625}
  condition: selection | count() > 10
"""
SIGMA_BADREGEX = """
title: Catastrophic
id: 55555555-5555-5555-5555-555555555555
logsource: {category: process_creation}
detection:
  selection: {CommandLine|re: '^(a+)+$'}
  condition: selection
"""
SIGMA_MATCHALL = """
title: Filter only
id: 66666666-6666-6666-6666-666666666666
logsource: {category: process_creation}
detection:
  filter: {User|contains: svc}
  condition: not filter
"""
YARA = """
import "pe"

rule Ransom_Note {
  strings:
    $a = "your files have been encrypted" nocase
    $b = "bitcoin"
  condition:
    any of them
}

rule Packed_PE {
  strings:
    $hex = { 4D 5A 90 00 }
  condition:
    $hex at 0 and pe.number_of_sections > 5
}
"""


def make_repo(root: Path, git: bool = False) -> Path:
    repo = root / "repo"
    (repo / "rules/windows").mkdir(parents=True)
    (repo / "yara").mkdir()
    files = {
        "rules/windows/clean.yml": SIGMA_CLEAN, "rules/windows/lossy.yml": SIGMA_LOSSY,
        "rules/windows/deprecated.yml": SIGMA_DEPRECATED, "rules/windows/agg.yml": SIGMA_AGG,
        "rules/windows/badregex.yml": SIGMA_BADREGEX, "rules/windows/matchall.yml": SIGMA_MATCHALL,
        "rules/windows/broken.yml": "title: x\ndetection:\n  selection: {Image: [\n",
        "yara/ransom.yar": YARA,
    }
    for rel, text in files.items():
        (repo / rel).write_text(text)
    if git:
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fixture"], cwd=repo, check=True)
    return repo


@pytest.fixture
def synced(tmp_path):
    repo = make_repo(tmp_path)
    src = add_source(str(repo), "fixture", tmp_path / "sources", license="TEST-1.0", paths=["rules", "yara"])
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache", sources_dir=tmp_path / "sources")
    return tmp_path, src, rep


# ---------------------------------------------------------------- importers report fidelity
def test_sigma_import_reports_notes_and_meta():
    imp = sigma_import(SIGMA_CLEAN)
    assert imp.notes == [] and imp.rule["sequence"][0]["event"] == "process.start"
    assert imp.meta["status"] == "test" and imp.meta["falsepositives"] == ["Admin scripts"]
    lossy = sigma_import(SIGMA_LOSSY)
    assert any("|base64offset" in n for n in lossy.notes)


def test_sigma_import_rejects_what_chain_cannot_run():
    with pytest.raises(SigmaUnsupported, match="aggregation"):
        sigma_import(SIGMA_AGG)
    with pytest.raises(SigmaUnsupported, match="correlation"):
        sigma_import("title: c\ncorrelation: {type: event_count}\n")
    with pytest.raises(SigmaUnsupported, match="invalid regex"):
        sigma_import("title: r\nlogsource: {category: process_creation}\ndetection:\n  s: {CommandLine|re: '('}\n  condition: s\n")


def test_sigma_unmapped_logsource_still_scopes_the_rule():
    imp = sigma_import("title: t\nlogsource: {product: linux, category: weird_cat}\ndetection:\n  s: {a: 1}\n  condition: s\n")
    assert imp.rule["sequence"][0]["event"] == "linux.weird_cat" and imp.notes == []
    app = sigma_import("title: t\nlogsource: {product: django, category: application}\ndetection:\n  s: {a: 1}\n  condition: s\n")
    assert app.rule["sequence"][0]["event"] == "log.django.application"
    svc = sigma_import("title: t\nlogsource: {product: windows, service: security}\ndetection:\n  s: {EventID: 1}\n  condition: s\n")
    assert svc.rule["sequence"][0]["event"] == "log.windows.security" and svc.notes == []


def test_sigma_new_modifiers_evaluate():
    rule = load_rule(sigma_import("title: w\nlogsource: {category: process_creation}\ndetection:\n"
                                  "  s: {CommandLine|windash|contains: ' -enc '}\n  condition: s\n").rule)
    eng = Engine([rule])
    assert eng.evaluate(Event(type="process.start", fields={"CommandLine": "powershell /enc AAAA"})).hits
    assert not eng.evaluate(Event(type="process.start", fields={"CommandLine": "powershell -nop"})).hits
    cased = load_rule(sigma_import("title: c\nlogsource: {category: process_creation}\ndetection:\n"
                                   "  s: {Image|cased|endswith: 'Mimikatz.exe'}\n  condition: s\n").rule)
    eng = Engine([cased])
    assert eng.evaluate(Event(type="process.start", fields={"Image": "C:\\Mimikatz.exe"})).hits
    assert not eng.evaluate(Event(type="process.start", fields={"Image": "C:\\mimikatz.exe"})).hits


def test_sigma_cidr_and_escaped_wildcards():
    def rule(sel):
        return load_rule(sigma_import(f"title: t\nlogsource: {{category: process_creation}}\ndetection:\n  s: {sel}\n  condition: s\n").rule)
    eng = Engine([rule("{SourceIp|cidr: [10.0.0.0/8, 'fe80::/10']}")])
    assert eng.evaluate(Event(type="process.start", fields={"SourceIp": "10.4.5.6"})).hits
    assert eng.evaluate(Event(type="process.start", fields={"SourceIp": "fe80::1"})).hits
    assert not eng.evaluate(Event(type="process.start", fields={"SourceIp": "8.8.8.8"})).hits
    assert not eng.evaluate(Event(type="process.start", fields={"SourceIp": "not-an-ip"})).hits
    # `not selection` over a cidr list is the public-IP pattern; it must not fire on private or empty
    pub = load_rule(sigma_import("title: p\nlogsource: {category: process_creation}\ndetection:\n"
                                 "  priv: {SourceIp|cidr: 10.0.0.0/8}\n  condition: not priv\n").rule)
    eng = Engine([pub])
    assert not eng.evaluate(Event(type="process.start", fields={"SourceIp": "10.1.1.1"})).hits
    assert eng.evaluate(Event(type="process.start", fields={"SourceIp": "1.2.3.4"})).hits

    eng = Engine([rule("{CommandLine|contains: '+S +A \\*.cui'}")])       # Sigma \* = literal *
    assert eng.evaluate(Event(type="process.start", fields={"CommandLine": "attrib +S +A *.cui"})).hits
    assert not eng.evaluate(Event(type="process.start", fields={"CommandLine": "attrib +S +A x.cui"})).hits
    eng = Engine([rule("{Image: 'C:\\\\Windows\\\\*\\\\cmd.exe'}")])                  # plain backslashes + wildcard
    assert eng.evaluate(Event(type="process.start", fields={"Image": "C:\\Windows\\System32\\cmd.exe"})).hits
    assert not eng.evaluate(Event(type="process.start", fields={"Image": "C:\\Windows\\System32\\cmd.exe.bak"})).hits
    eng = Engine([rule("{CommandLine|contains: 'a[1]b'}")])                   # [ is not a character class
    assert eng.evaluate(Event(type="process.start", fields={"CommandLine": "x a[1]b y"})).hits


def test_yara_import_delegates_instead_of_dropping():
    imps = yara_import(YARA)
    assert [i.name for i in imps] == ["Ransom_Note", "Packed_PE"]
    assert not imps[0].delegated and imps[1].delegated
    assert 'import "pe"' in imps[1].source and "4D 5A" in imps[1].source
    eng = Engine([load_rule(imps[1].rule)])
    assert eng.evaluate(Event(type="file.scan", fields={"yara_matches": ["Packed_PE"]})).hits
    assert not eng.evaluate(Event(type="file.scan", fields={"yara_matches": ["Other"]})).hits


# ---------------------------------------------------------------- safety
def test_regex_safety():
    assert check_regex(r"(a+)+$") is not None
    assert check_regex(r"(") is not None
    assert check_regex(r"powershell.*-enc") is None


def test_match_everything_and_unconstrained_flags():
    assert "matches an empty event of its own type" in check_rule(load_rule(sigma_import(SIGMA_MATCHALL).rule))
    bare = load_rule({"id": "bare", "sequence": [{"name": "a"}]})
    assert any("no event type and no constraint" in f for f in check_rule(bare))
    assert check_rule(load_rule(sigma_import(SIGMA_CLEAN).rule)) == []


# ---------------------------------------------------------------- sync pipeline
def test_sync_outcomes_and_fidelity(synced):
    tmp, src, rep = synced
    assert rep.files == 8
    assert (rep.imported, rep.failed, rep.skipped, rep.flagged) == (6, 2, 1, 2)
    assert rep.by_fidelity() == {"exact": 4, "lossy": 1, "delegated": 1}
    assert rep.changes() == {"added": 6, "updated": 0, "unchanged": 0, "removed": 0}
    by_path = {i.path: i for i in rep.items}
    assert by_path["rules/windows/deprecated.yml"].reason == "status deprecated"
    assert "aggregation" in by_path["rules/windows/agg.yml"].reason
    assert by_path["rules/windows/broken.yml"].outcome == "failed"
    assert by_path["rules/windows/badregex.yml"].flags and by_path["rules/windows/matchall.yml"].flags
    assert rep.license == "TEST-1.0"
    assert ("unsupported modifier |base64offset ignored", 1) in rep.note_counts()


def test_sync_writes_corpus_index_report_and_origin(synced):
    tmp, src, rep = synced
    out = tmp / "corpus/fixture"
    rule = yaml.safe_load((out / "rules/windows/lossy.yaml").read_text())
    o = rule["origin"]
    assert o["source"] == "fixture" and o["format"] == "sigma" and o["fidelity"] == "lossy"
    assert o["license"] == "TEST-1.0" and o["path"] == "rules/windows/lossy.yml" and len(o["upstream_sha256"]) == 64
    assert "native" not in o
    delegated = yaml.safe_load((out / "yara/ransom/Packed_PE.yaml").read_text())
    assert delegated["origin"]["fidelity"] == "delegated" and "rule Packed_PE" in delegated["origin"]["native"]
    flagged = yaml.safe_load((out / "rules/windows/badregex.yaml").read_text())
    assert any(n.startswith("safety:") for n in flagged["origin"]["notes"])

    index = json.loads((out / "index.json").read_text())
    assert len(index["rules"]) == 6 and index["license"] == "TEST-1.0"
    assert index["rules"]["sigma_55555555_5555_5555_5555_555555555555"]["flags"] is True
    report = json.loads((out / "report.json").read_text())
    assert report["summary"]["imported"] == 6
    manifest = load_source("fixture", tmp / "sources")
    assert manifest.last_sync == rep.started


def test_corpus_loads_in_engine_and_fires(synced):
    tmp, _, _ = synced
    eng = Engine.from_paths(tmp / "corpus/fixture")
    assert len(eng.rules) == 6
    v = eng.evaluate(Event(type="process.start", fields={"Image": r"C:\powershell.exe", "CommandLine": "powershell -enc AAAA"}))
    assert [h.rule_id for h in v.hits if h.rule_id.startswith("sigma_1111")]
    assert eng.evaluate(Event(type="file.scan", fields={"content": "pay in bitcoin now"})).hits


def test_resync_reports_changes_and_removes_stale_rules(synced):
    tmp, src, _ = synced
    repo = Path(src.url)
    (repo / "rules/windows/lossy.yml").write_text(SIGMA_LOSSY.replace("Private range", "Private range v2"))
    (repo / "rules/windows/clean.yml").unlink()
    (repo / "rules/windows/new.yml").write_text(SIGMA_CLEAN.replace("1111", "9999"))
    rep = sync_source(src, tmp / "corpus", tmp / "cache")
    assert rep.changes() == {"added": 1, "updated": 1, "unchanged": 4, "removed": 1}
    assert rep.removed == ["sigma_11111111_1111_1111_1111_111111111111"]
    assert not (tmp / "corpus/fixture/rules/windows/clean.yaml").exists()
    assert (tmp / "corpus/fixture/rules/windows/new.yaml").exists()


def test_strict_mode_fails_on_flags(synced):
    tmp, src, _ = synced
    rep = sync_source(src, tmp / "corpus", tmp / "cache", strict=True)
    assert not rep.ok and rep.flagged == 0 and rep.failed == 4   # flagged rules become failures
    assert not (tmp / "corpus/fixture/rules/windows/badregex.yaml").exists()


def test_exclude_and_duplicate_ids(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "rules/windows/dup.yml").write_text(SIGMA_CLEAN)
    src = add_source(str(repo), "fx", tmp_path / "sources", paths=["rules"], exclude=["rules/windows/broken.yml"])
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache")
    assert rep.files == 7
    dup = [i for i in rep.items if i.path == "rules/windows/dup.yml"][0]
    assert dup.outcome == "failed" and "duplicate id" in dup.reason


# ---------------------------------------------------------------- git sources, pinned
def test_git_source_pins_and_fetches_by_commit(tmp_path):
    repo = make_repo(tmp_path, git=True)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()
    src = add_source(repo.as_uri(), "pinned", tmp_path / "sources", paths=["rules"])
    assert src.ref == sha
    checkout = fetch(src, tmp_path / "cache")
    assert (checkout / "rules/windows/clean.yml").exists() and checkout != repo

    # upstream moves on; the pin keeps the corpus where it was until --update
    (repo / "rules/windows/later.yml").write_text(SIGMA_CLEAN.replace("1111", "8888"))
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "later"], cwd=repo, check=True)
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache", sources_dir=tmp_path / "sources")
    assert not any(i.path.endswith("later.yml") for i in rep.items)
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache", update=True, sources_dir=tmp_path / "sources")
    assert src.ref != sha and any(i.path.endswith("later.yml") for i in rep.items)
    assert load_source("pinned", tmp_path / "sources").ref == src.ref


# ---------------------------------------------------------------- CLI
def test_cli_add_list_sync_status(tmp_path, capsys):
    repo = make_repo(tmp_path)
    common = ["--sources", str(tmp_path / "s"), "--corpus", str(tmp_path / "c"), "--cache", str(tmp_path / "k")]
    assert main(["sources", "add", str(repo), "--name", "fx", "--paths", "rules", "yara", "--license", "T", *common]) == 0
    assert main(["sources", "list", *common]) == 0
    assert "fx" in capsys.readouterr().out
    assert main(["sources", "sync", *common]) == 0
    out = capsys.readouterr().out
    assert "imported 6 (exact 4, lossy 1, delegated 1)" in out
    assert main(["sources", "sync", "--strict", *common]) == 1
    capsys.readouterr()
    assert main(["sources", "status", *common]) == 0
    assert "fx" in capsys.readouterr().out
    assert main(["sources", "sync", "--json", *common]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["summary"]["fidelity"]["exact"] == 4
    assert len(list_sources(tmp_path / "s")) == 1
