"""Phase B, Suricata: parser, native evaluation of app-layer buffers, thresholds, flowbits, delegation, pipeline."""
import pytest

from chain import Engine, Event, load_rule
from chain.corpus.pipeline import sync_source
from chain.corpus.sources import add_source
from chain.importers.suricata import convert, link_flowbits, suricata_import
from chain.suricata import (SuricataDetection, SuricataSyntax, SuricataUnsupported, content_bytes, parse_file, parse_rule,
                            resolve_addr, resolve_port)

BEACON = ('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Fake Beacon POST"; flow:established,to_server; '
          'http.method; content:"POST"; http.uri; content:"/gate.php"; endswith; http.user_agent; content:"Mozilla/4.0"; depth:11; nocase; '
          'classtype:trojan-activity; metadata:signature_severity Major, malware_family FakeBeacon, mitre_technique_id T1071; '
          'reference:url,example.com; sid:2000001; rev:3;)')


def ev(type_="net.http", **fields) -> Event:
    return Event(type=type_, fields=fields)


def det(rule_text: str, variables=None) -> SuricataDetection:
    imp = convert(parse_rule(rule_text), variables)
    assert not imp.delegated, imp.notes
    return SuricataDetection(imp.rule["sequence"][0]["where"]["suricata"])


# ---------------------------------------------------------------- parsing
def test_parse_rule_header_and_options():
    r = parse_rule(BEACON)
    assert (r.action, r.proto, r.src, r.sport, r.direction, r.dst, r.dport) == ("alert", "http", "$HOME_NET", "any", "->", "$EXTERNAL_NET", "any")
    assert r.opt("sid") == "2000001" and r.opt("msg") == '"ET MALWARE Fake Beacon POST"'
    assert ("http.uri", None) in r.options and ("endswith", None) in r.options
    quoted = parse_rule('alert http any any -> any any (msg:"a;b \\"c\\""; content:"x|3b 20|y\\;z"; http.uri; sid:1;)')
    assert quoted.opt("msg") == '"a;b \\"c\\""'
    assert content_bytes(quoted.opt("content")) == b"x; y;z"
    assert content_bytes('"|4D 5A|"') == b"MZ" and content_bytes('"a\\\\b"') == b"a\\b"
    with pytest.raises(SuricataSyntax):
        parse_rule("alert http any any -> any any (msg:\"no sid\";)")


def test_parse_file_handles_comments_and_continuations():
    text = ('# a comment\n'
            '#alert dns any any -> any any (msg:"disabled"; dns.query; content:"evil"; sid:10;)\n'
            'alert dns any any -> any any (msg:"split"; \\\n   dns.query; content:"bad"; sid:11;)\n'
            'random line\n')
    rules = parse_file(text)
    assert [(ln, c) for ln, _, c in rules] == [(2, True), (3, False)]
    assert "dns.query; content:\"bad\"" in rules[1][1]
    assert [i.sid for i in suricata_import(text)] == ["11"]
    assert [i.sid for i in suricata_import(text, include_disabled=True)] == ["10", "11"]


# ---------------------------------------------------------------- addresses and ports
def test_variables_negation_and_ranges():
    from chain.suricata import DEFAULT_VARS
    notes = []
    home = resolve_addr("$HOME_NET", DEFAULT_VARS, notes)
    assert home.matches("10.1.2.3") and not home.matches("8.8.8.8")
    ext = resolve_addr("$EXTERNAL_NET", DEFAULT_VARS, notes)
    assert ext.matches("8.8.8.8") and not ext.matches("192.168.1.1")
    mixed = resolve_addr("[10.0.0.0/8,!10.1.0.0/16]", DEFAULT_VARS, notes)
    assert mixed.matches("10.2.0.1") and not mixed.matches("10.1.0.1") and not mixed.matches("1.1.1.1")
    assert resolve_addr("any", {}, notes).matches("1.2.3.4") and not resolve_addr("any", {}, notes).matches("junk")
    unknown = resolve_addr("$NOPE", {}, notes)
    assert unknown.matches("1.1.1.1") and any("$NOPE" in n for n in notes)
    p = resolve_port("[80,443,8000:8080,!8005]", DEFAULT_VARS, notes)
    assert p.matches(80) and p.matches("8010") and not p.matches(8005) and not p.matches(22)
    assert resolve_port("$HTTP_PORTS", DEFAULT_VARS, notes).matches(80)
    assert resolve_port("!22", {}, notes).matches(80) and not resolve_port("!22", {}, notes).matches(22)
    assert resolve_port("1024:", {}, notes).matches(5000) and not resolve_port("1024:", {}, notes).matches(80)


def test_header_is_checked_when_the_event_carries_addresses():
    d = det('alert http $HOME_NET any -> $EXTERNAL_NET 80 (msg:"h"; http.uri; content:"/x"; sid:1;)')
    hit = {"http": {"url": "/x"}}
    assert d.matches(ev(src_ip="10.0.0.5", dest_ip="1.2.3.4", dest_port=80, **hit))
    assert not d.matches(ev(src_ip="1.2.3.4", dest_ip="10.0.0.5", dest_port=80, **hit))      # wrong direction
    assert not d.matches(ev(src_ip="10.0.0.5", dest_ip="1.2.3.4", dest_port=8080, **hit))
    assert d.matches(ev(**hit))                                                              # no addresses: can't fail on them
    bi = det('alert http 10.0.0.1 any <> 10.0.0.2 any (msg:"bi"; http.uri; content:"/x"; sid:2;)')
    assert bi.matches(ev(src_ip="10.0.0.2", dest_ip="10.0.0.1", **hit)) and bi.matches(ev(src_ip="10.0.0.1", dest_ip="10.0.0.2", **hit))


# ---------------------------------------------------------------- buffers and position semantics
def test_sticky_buffers_and_aliases():
    d = det(BEACON)
    good = dict(http={"http_method": "POST", "url": "/panel/gate.php", "http_user_agent": "mozilla/4.0 (compatible)"})
    assert d.matches(ev(**good))
    assert d.matches(ev(**{"cs-method": "POST", "c-uri": "/gate.php", "cs-user-agent": "Mozilla/4.0"}))   # Sigma-style names
    assert d.matches(ev(url="/gate.php", method="POST", user_agent="Mozilla/4.0 x"))                   # tool-bridge names
    assert not d.matches(ev(http={"http_method": "GET", "url": "/gate.php", "http_user_agent": "Mozilla/4.0"}))
    assert not d.matches(ev(http={"http_method": "POST", "url": "/gate.php?x=1", "http_user_agent": "Mozilla/4.0"}))   # endswith
    assert not d.matches(ev(http={"http_method": "POST", "url": "/gate.php", "http_user_agent": "x Mozilla/4.0"}))     # depth:11
    assert not d.matches(ev(http={"http_method": "POST", "url": "/gate.php"}))                                       # buffer missing


def test_depth_offset_distance_within_negation_and_isdataat():
    d = det('alert http any any -> any any (msg:"p"; http.uri; content:"/a"; depth:2; content:"b"; distance:1; within:1; content:!"zzz"; sid:3;)')
    assert d.matches(ev(url="/a.b")) and not d.matches(ev(url="/ab")) and not d.matches(ev(url="x/a.b")) and not d.matches(ev(url="/a.bzzz"))
    off = det('alert http any any -> any any (msg:"o"; http.uri; content:"x"; offset:2; depth:1; sid:4;)')
    assert off.matches(ev(url="..x")) and not off.matches(ev(url="x..")) and not off.matches(ev(url="...x"))
    sw = det('alert http any any -> any any (msg:"s"; http.uri; content:"/adm"; startswith; sid:5;)')
    assert sw.matches(ev(url="/admin")) and not sw.matches(ev(url="x/adm"))
    isd = det('alert http any any -> any any (msg:"i"; http.uri; content:"/a"; isdataat:!1,relative; sid:6;)')
    assert isd.matches(ev(url="/a")) and not isd.matches(ev(url="/abc"))
    bs = det('alert dns any any -> any any (msg:"b"; dns.query; content:"."; bsize:<8; sid:7;)')
    assert bs.matches(ev("net.dns", dns={"rrname": "a.b.c"})) and not bs.matches(ev("net.dns", QueryName="toolongname.example"))
    ul = det('alert http any any -> any any (msg:"u"; urilen:>5; http.uri; content:"/"; sid:8;)')
    assert ul.matches(ev(url="/abcdef")) and not ul.matches(ev(url="/ab"))


def test_legacy_modifiers_pcre_flags_and_transforms():
    d = det('alert tcp any any -> any any (msg:"legacy"; content:"GET"; http_method; content:"/x.php"; http_uri; nocase; pcre:"/\\.php$/Ui"; sid:9;)')
    assert d.matches(ev(http={"http_method": "GET", "url": "/X.PHP"}))
    assert not d.matches(ev(http={"http_method": "GET", "url": "/x.phpx"}))
    assert d.matches(ev(**{"cs-method": "GET", "c-uri": "/x.php"}))
    rel = det('alert http any any -> any any (msg:"rel"; http.uri; content:"id="; pcre:"/^\\d+/R"; sid:10;)')
    assert rel.matches(ev(url="/a?id=123")) and not rel.matches(ev(url="/a?id=abc"))
    lower = det('alert http any any -> any any (msg:"t"; http.host; to_lowercase; content:"evil.example"; sid:11;)')
    assert lower.matches(ev(http={"hostname": "EVIL.Example"}))
    dot = det('alert dns any any -> any any (msg:"d"; dns.query; dotprefix; content:".evil.com"; endswith; sid:12;)')
    assert dot.matches(ev("net.dns", QueryName="evil.com")) and dot.matches(ev("net.dns", QueryName="x.evil.com"))
    assert not dot.matches(ev("net.dns", QueryName="notevil.com"))


def test_app_layer_events_and_int_keywords():
    d = det('alert http any any -> any any (msg:"anomaly"; flow:established; app-layer-event:http.unknown_error; sid:13;)')
    assert d.matches(ev(app_layer_event="http.unknown_error")) and d.matches(ev(anomaly={"event": "http.unknown_error"}))
    assert not d.matches(ev(app_layer_event="http.other"))
    imp = convert(parse_rule('alert pkthdr any any -> any any (msg:"dec"; decode-event:ipv4.hlen_too_small; sid:60;)'))
    assert imp.rule["sequence"][0]["event"] == "net.anomaly"
    dd = SuricataDetection(imp.rule["sequence"][0]["where"]["suricata"])
    assert dd.matches(ev("net.anomaly", anomaly={"type": "decode", "event": "ipv4.hlen_too_small"}))
    sc = det('alert http any any -> any any (msg:"404"; http.stat_code:404; sid:14;)')
    assert sc.matches(ev(http={"status": 404})) and not sc.matches(ev(http={"status": 200}))


# ---------------------------------------------------------------- conversions
def test_severity_tags_actions_and_metadata():
    imp = convert(parse_rule(BEACON))
    r = imp.rule
    assert r["id"] == "suricata_2000001" and r["severity"] == "high" and r["title"] == "ET MALWARE Fake Beacon POST"
    assert {"classtype:trojan-activity", "attack:T1071", "malware:FakeBeacon"} <= set(r["tags"])
    assert r["sequence"][0]["event"] == "net.http" and imp.meta["references"] == ["url,example.com"]
    drop = convert(parse_rule('drop dns any any -> any any (msg:"d"; dns.query; content:"x"; sid:15;)'))
    assert drop.rule["action"] == "block" and drop.rule["sequence"][0]["event"] == "net.dns"
    ct = convert(parse_rule('alert tls any any -> any any (msg:"c"; tls.sni; content:"x"; classtype:command-and-control; sid:16;)'))
    assert ct.rule["severity"] == "critical" and ct.rule["sequence"][0]["event"] == "net.tls"


def test_threshold_and_detection_filter_become_count_steps():
    imp = convert(parse_rule('alert dns $HOME_NET any -> any any (msg:"many"; dns.query; content:".evil"; '
                             'threshold:type threshold, track by_src, count 5, seconds 60; sid:17;)'))
    assert imp.rule["sequence"][0]["count"] == {"min": 5, "within": 60.0} and imp.rule["group_by"] == "fields.src_ip"
    df = convert(parse_rule('alert http any any -> any any (msg:"df"; http.uri; content:"/login"; '
                            'detection_filter:track by_dst, count 10, seconds 30; sid:18;)'))
    assert df.rule["sequence"][0]["count"] == {"min": 11, "within": 30.0} and df.rule["group_by"] == "fields.dest_ip"
    lim = convert(parse_rule('alert http any any -> any any (msg:"l"; http.uri; content:"/x"; threshold:type limit, track by_src, count 1, seconds 60; sid:19;)'))
    assert "count" not in lim.rule["sequence"][0] and lim.notes == [] and "limit" in lim.meta["rate_limit"]
    eng = Engine([load_rule(imp.rule)])
    fired = [bool(eng.evaluate(Event(type="net.dns", ts=i, fields={"src_ip": "10.0.0.9", "QueryName": "a.evil"})).hits) for i in range(5)]
    assert fired == [False] * 4 + [True]


def test_flowbits_link_into_a_sequence():
    text = ('alert http any any -> any any (msg:"stage1"; http.uri; content:"/stage1"; flowbits:set,stage1; flowbits:noalert; sid:20;)\n'
            'alert http any any -> any any (msg:"stage2"; http.uri; content:"/stage2"; flowbits:isset,stage1; sid:21;)\n'
            'alert http any any -> any any (msg:"orphan"; http.uri; content:"/o"; flowbits:isset,never_set; sid:22;)\n')
    imps = suricata_import(text)
    link_flowbits(imps)
    by = {i.sid: i for i in imps}
    assert by["20"].rule["action"] == "allow"
    seq = by["21"].rule["sequence"]
    assert [s["name"] for s in seq] == ["flowbit_stage1", "match"] and by["21"].rule["group_by"] == ["fields.flow_id"]
    assert any("never_set" in n for n in by["22"].notes) and len(by["22"].rule["sequence"]) == 1
    eng = Engine([load_rule(by["21"].rule)])
    assert not eng.evaluate(Event(type="net.http", fields={"flow_id": 1, "url": "/stage2"})).hits
    eng.evaluate(Event(type="net.http", fields={"flow_id": 1, "url": "/stage1"}))
    assert not eng.evaluate(Event(type="net.http", fields={"flow_id": 2, "url": "/stage2"})).hits   # other flow
    assert eng.evaluate(Event(type="net.http", fields={"flow_id": 1, "url": "/stage2"})).hits


def test_payload_rules_are_delegated_with_reasons():
    cases = {
        'alert tcp any any -> any 4444 (msg:"raw"; content:"|00 01|"; sid:30;)': "raw payload",
        'alert http any any -> any any (msg:"bt"; http.uri; content:"/x"; byte_test:2,>,100,0,relative; sid:31;)': "byte_test",
        'alert ip any any -> any any (msg:"hdr"; ip_proto:47; sid:32;)': "ip_proto",
        'alert tcp $HOME_NET any -> any any (msg:"sz"; dsize:>1000; sid:33;)': "dsize",
        'alert udp any any -> any 53 (msg:"hdronly"; sid:34;)': "header-only",
    }
    for text, reason in cases.items():
        imp = suricata_import(text)[0]
        assert imp.delegated and reason in imp.notes[0], (text, imp.notes)
        assert imp.rule["sequence"][0]["where"] == {"fields.alert.signature_id": int(imp.sid)}
    with pytest.raises(SuricataUnsupported):
        convert(parse_rule('alert http any any -> any any (msg:"mix"; http.uri; content:"a"; dns.query; content:"b"; sid:35;)'))


def test_delegated_rule_matches_suricata_alert_events():
    imp = suricata_import('alert tcp any any -> any 4444 (msg:"raw"; content:"|00 01|"; sid:30;)')[0]
    eng = Engine([load_rule(imp.rule)])
    assert eng.evaluate(Event(type="net.alert", fields={"alert": {"signature_id": 30, "signature": "raw"}})).hits
    assert not eng.evaluate(Event(type="net.alert", fields={"alert": {"signature_id": 31}})).hits


# ---------------------------------------------------------------- pipeline
def test_pipeline_syncs_a_rules_file(tmp_path):
    repo = tmp_path / "repo"
    (repo / "rules").mkdir(parents=True)
    (repo / "rules/emerging-test.rules").write_text(
        BEACON + "\n"
        '# alert http any any -> any any (msg:"disabled"; http.uri; content:"/d"; sid:40;)\n'
        'alert tcp any any -> any 4444 (msg:"raw"; content:"|00 01|"; sid:41;)\n'
        'alert dns any any -> any any (msg:"unknown var"; dns.query; content:"x"; sid:42;)\n'
        'alert http $WEIRD any -> any any (msg:"lossy"; http.uri; content:"/l"; sid:43;)\n'
        'this is not a rule\n')
    src = add_source(str(repo), "sur", tmp_path / "sources", paths=["rules"], license="BSD")
    rep = sync_source(src, tmp_path / "corpus", tmp_path / "cache")
    assert rep.failed == 0 and rep.by_fidelity() == {"exact": 2, "lossy": 1, "delegated": 1}
    by = {i.path: i for i in rep.items}
    assert any("$WEIRD" in n for n in by["rules/emerging-test.rules#43"].notes)
    eng = Engine.from_paths(tmp_path / "corpus/sur")
    assert len(eng.rules) == 4
    v = eng.evaluate(Event(type="net.http", fields={"http": {"http_method": "POST", "url": "/gate.php", "http_user_agent": "Mozilla/4.0"}}))
    assert "suricata_2000001" in {h.rule_id for h in v.hits}
    assert (tmp_path / "corpus/sur/rules/emerging-test/2000001.yaml").exists()
    native = (tmp_path / "corpus/sur/rules/emerging-test/41.yaml").read_text()
    assert "native:" in native and "sid:41" in native


def test_tool_bridge_http_events_reach_suricata_rules():
    from chain import ChainGuard
    imp = convert(parse_rule('alert http any any -> any any (msg:"paste"; http.host; content:"paste.example"; http.method; content:"POST"; sid:50;)'))
    eng = Engine([load_rule(imp.rule)])
    g = ChainGuard(eng, session_id="s", enforce=False, platform="linux")
    v = g.pre_tool_call("http_post", {"url": "https://paste.example/new"})
    assert "suricata_50" in {h.rule_id for h in v.hits}
    assert g.pre_tool_call("http_get", {"url": "https://paste.example/new"}).action == "allow"
