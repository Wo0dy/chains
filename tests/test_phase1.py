"""Absence ("not followed by"), counting and replay scoring."""
import json
from pathlib import Path

import pytest

from chain import ChainGuard, Engine, Event, load_rule
from chain.cli import main
from chain.replay import replay

ROOT = Path(__file__).resolve().parent.parent


def ev(type_, ts, **kw):
    return Event(type=type_, ts=ts, **kw)


# ---------------------------------------------------------------- absence: middle
MIDDLE = {
    "id": "mid", "group_by": "user",
    "sequence": [
        {"name": "a", "event": "x.a"},
        {"name": "no_b", "event": "x.b", "absent": True},
        {"name": "c", "event": "x.c"},
    ],
}


def test_middle_absence_fires_when_forbidden_event_missing():
    eng = Engine([load_rule(MIDDLE)])
    eng.evaluate(ev("x.a", 1, user="u"))
    eng.evaluate(ev("x.noise", 2, user="u"))
    v = eng.evaluate(ev("x.c", 3, user="u"))
    assert v.hits
    steps = [e.step for e in v.hits[0].evidence]
    assert steps == ["a", "no_b", "c"]
    assert v.hits[0].evidence[1].event_type == "absent"


def test_middle_absence_killed_by_forbidden_event():
    eng = Engine([load_rule(MIDDLE)])
    eng.evaluate(ev("x.a", 1, user="u"))
    eng.evaluate(ev("x.b", 2, user="u"))
    assert not eng.evaluate(ev("x.c", 3, user="u")).hits


def test_forbidden_event_in_other_group_does_not_kill():
    eng = Engine([load_rule(MIDDLE)])
    eng.evaluate(ev("x.a", 1, user="u"))
    eng.evaluate(ev("x.b", 2, user="someone-else"))
    assert eng.evaluate(ev("x.c", 3, user="u")).hits


def test_absent_step_respects_same():
    rule = load_rule({
        "id": "s",
        "sequence": [
            {"name": "a", "event": "x.a"},
            {"name": "no_b", "event": "x.b", "absent": True, "same": ["host"]},
            {"name": "c", "event": "x.c"},
        ],
    })
    eng = Engine([rule])
    eng.evaluate(ev("x.a", 1, host="h1"))
    eng.evaluate(ev("x.b", 2, host="h2"))          # different host: doesn't cancel
    assert eng.evaluate(ev("x.c", 3, host="h1")).hits


# ---------------------------------------------------------------- absence: final
FINAL = {
    "id": "fin", "group_by": "user", "action": "block",
    "sequence": [
        {"name": "a", "event": "x.a"},
        {"name": "no_b", "event": "x.b", "absent": True, "within": 60},
    ],
}


def test_final_absence_fires_via_advance_time_only():
    eng = Engine([load_rule(FINAL)])
    v = eng.evaluate(ev("x.a", 100, user="u"))
    assert not v.hits
    assert eng.advance_time(159) == []
    out = eng.advance_time(160)
    assert len(out) == 1 and out[0].deferred and out[0].event_id == v.event_id
    assert out[0].hits[0].evidence[-1].details == ["no x.b within 60s"]
    assert eng.advance_time(500) == []                 # fires once


def test_final_absence_cancelled_by_event_in_time():
    eng = Engine([load_rule(FINAL)])
    eng.evaluate(ev("x.a", 100, user="u"))
    eng.evaluate(ev("x.b", 130, user="u"))
    assert eng.advance_time(1000) == []


def test_due_absence_never_lands_in_unrelated_verdict():
    eng = Engine([load_rule(FINAL)])
    eng.evaluate(ev("x.a", 100, user="u"))
    later = eng.evaluate(ev("x.other", 500, user="u"))  # arrives after the deadline
    assert not later.hits and later.action == "allow"
    out = eng.advance_time(500)
    assert len(out) == 1 and out[0].action == "block"


def test_absence_survives_rule_window_expiry():
    rule = load_rule({**FINAL, "window": {"seconds": 30}})
    eng = Engine([rule])
    eng.evaluate(ev("x.a", 100, user="u"))
    eng.evaluate(ev("x.other", 200, user="u"))          # would expire the partial
    assert len(eng.advance_time(200)) == 1


def test_evaluate_many_includes_deferred_verdicts():
    eng = Engine([load_rule(FINAL)])
    out = eng.evaluate_many([ev("x.a", 0, user="u"), ev("x.other", 100, user="u")])
    assert [v.deferred for v in out] == [False, True, False]


def test_guard_tick_reports_but_never_raises():
    seen = []
    eng = Engine([load_rule({**FINAL, "sequence": [
        {"name": "a", "event": "ai.prompt"},
        {"name": "no_b", "event": "ai.output", "absent": True, "within": 60},
    ]})])
    guard = ChainGuard(eng, session_id="s", on_verdict=seen.append)
    guard.on_prompt("hello")
    import time
    out = guard.tick(time.time() + 61)
    assert len(out) == 1 and seen == out


# ---------------------------------------------------------------- counting
def count_rule(**count):
    return load_rule({"id": "cnt", "group_by": "host",
                      "sequence": [{"name": "n", "event": "x.e", "count": {"min": 3, "within": 10, **count}}]})


def test_count_fires_at_threshold_and_resets():
    eng = Engine([count_rule()])
    fired = [bool(eng.evaluate(ev("x.e", t, host="h")).hits) for t in range(6)]
    assert fired == [False, False, True, False, False, True]


def test_count_window_slides():
    eng = Engine([count_rule()])
    fired = [bool(eng.evaluate(ev("x.e", t, host="h")).hits) for t in (0, 8, 16, 24, 25)]
    assert fired == [False, False, False, False, True]   # only 16, 24, 25 fall within 10s of each other


def test_count_is_per_group():
    eng = Engine([count_rule()])
    for t, h in enumerate(["a", "b", "c", "a", "b"]):
        assert not eng.evaluate(ev("x.e", t, host=h)).hits
    assert eng.evaluate(ev("x.e", 5, host="a")).hits


def test_count_distinct():
    eng = Engine([count_rule(distinct="fields.port")])
    ports = [80, 80, 80, 443, 80, 22]
    fired = [bool(eng.evaluate(ev("x.e", t, host="h", fields={"port": p})).hits) for t, p in enumerate(ports)]
    assert fired == [False, False, False, False, False, True]
    v_detail = Engine([count_rule(distinct="fields.port")])
    for t, p in enumerate([1, 2, 3]):
        last = v_detail.evaluate(ev("x.e", t, host="h", fields={"port": p}))
    assert "count: 3 distinct fields.port >= 3 within 10s" in last.hits[0].evidence[0].details


def test_count_then_next_step():
    rule = load_rule({
        "id": "bf", "group_by": "user",
        "sequence": [
            {"name": "fails", "event": "auth.login", "where": {"fields.outcome": "failure"},
             "count": {"min": 3, "within": 60}},
            {"name": "ok", "event": "auth.login", "where": {"fields.outcome": "success"}},
        ],
    })
    eng = Engine([rule])
    for t in range(3):
        eng.evaluate(ev("auth.login", t, user="u", fields={"outcome": "failure"}))
    v = eng.evaluate(ev("auth.login", 5, user="u", fields={"outcome": "success"}))
    assert v.hits
    assert not eng.evaluate(ev("auth.login", 6, user="u", fields={"outcome": "success"})).hits


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("seq, msg", [
    ([{"name": "a", "absent": True}], "first step"),
    ([{"name": "a"}, {"name": "b", "absent": True}], "needs within"),
    ([{"name": "a"}, {"name": "b", "absent": True, "within": 5}, {"name": "c"}], "final absent"),
    ([{"name": "a"}, {"name": "b", "absent": True}, {"name": "c", "absent": True, "within": 5}], "another absent"),
    ([{"name": "a"}, {"name": "b", "within": 5}], "needs absent"),
    ([{"name": "a"}, {"name": "b", "absent": True}, {"name": "c", "tainted_by": "b"}], "tainted_by absent"),
    ([{"name": "a"}, {"name": "b", "absent": True, "within": 5, "count": {"min": 2, "within": 5}}], "can't also count"),
])
def test_invalid_absence_rules_rejected(seq, msg):
    with pytest.raises(ValueError, match=msg):
        load_rule({"id": "bad", "sequence": seq})


def test_count_needs_min_two():
    with pytest.raises(Exception):
        load_rule({"id": "bad", "sequence": [{"name": "a", "count": {"min": 1, "within": 5}}]})


def test_within_accepts_seconds_mapping():
    r = load_rule({"id": "w", "sequence": [{"name": "a"}, {"name": "b", "absent": True, "within": {"seconds": 30}}]})
    assert r.steps[1].spec.within == 30


# ---------------------------------------------------------------- replay
def test_replay_scores_tp_fp_fn():
    rule = load_rule({"id": "r", "sequence": [{"name": "a", "event": "x.hit"}]})
    records = [
        {"id": "e1", "type": "x.hit", "ts": 1, "labels": ["r"]},       # TP
        {"id": "e2", "type": "x.hit", "ts": 2},                         # FP
        {"id": "e3", "type": "x.miss", "ts": 3, "labels": "r"},         # FN
        {"id": "e4", "type": "x.miss", "ts": 4, "labels": ["nope"]},    # unknown rule
    ]
    rep = replay(Engine([rule]), records)
    s = rep.rules[0]
    assert (s.tp, s.fp, s.fn) == (["e1"], ["e2"], ["e3"])
    assert s.precision == 0.5 and s.recall == 0.5
    assert rep.unknown_labels == ["nope"]
    assert rep.failures(min_precision=0.9) == ["r: precision 0.50 < 0.9"]
    assert "labels" not in records[0] or records[0]["labels"] == ["r"]   # input not mutated


def test_replay_credits_deferred_absence_to_anchor_event():
    rep = replay(Engine([load_rule(FINAL)]), [
        {"id": "a1", "type": "x.a", "ts": 0, "user": "u", "labels": ["fin"]},
        {"id": "n1", "type": "x.other", "ts": 100, "user": "u"},
    ])
    assert rep.rules[0].tp == ["a1"] and not rep.rules[0].fp


def test_bundled_labeled_dataset_passes_gate(capsys):
    rc = main(["replay", str(ROOT / "rules"), str(ROOT / "examples/labeled_events.jsonl"),
               "--baseline", str(ROOT / "examples/baseline_events.jsonl"),
               "--min-precision", "0.9", "--min-recall", "0.9", "--json"])
    report = json.loads(capsys.readouterr().out)
    assert rc == 0, report
    assert report["total"]["tp"] >= 8 and report["total"]["fp"] == 0
