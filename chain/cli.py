"""chain CLI

  chain validate RULES            compile rules, report errors
  chain test RULES                run inline rule tests
  chain fuzz RULES                mutation-fuzz positive tests, report recall per technique
  chain eval RULES EVENTS.jsonl   run events through the engine, print verdicts
  chain replay RULES LABELED.jsonl  score rules against labeled history (precision / recall)
  chain import-sigma FILE         convert a Sigma rule to Chain YAML
  chain import-yara FILE          convert simple YARA rules to Chain YAML
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .engine import Engine
from .importers.sigma import sigma_to_chain
from .importers.yara import yara_to_chain
from .replay import read_jsonl, replay
from .rules import load_rules
from .schema import Event
from .testing import fuzz, run_tests

DEFAULT_CLUSTERS = Path(__file__).resolve().parent.parent / "clusters"


def _engine(args) -> Engine:
    return Engine.from_paths(args.rules, args.clusters)


def cmd_validate(args) -> int:
    try:
        rules = load_rules(args.rules)
    except Exception as e:  # noqa: BLE001
        print(f"INVALID: {e}")
        return 1
    print(f"OK: {len(rules)} rules compiled")
    return 0


def cmd_test(args) -> int:
    eng = _engine(args)
    results = run_tests(eng.rules, eng)
    failed = 0
    for r in results:
        mark = "PASS" if r.passed else "FAIL"
        failed += not r.passed
        print(f"{mark}  {r.rule_id:40s} {r.case:35s} {r.detail}")
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


def cmd_fuzz(args) -> int:
    eng = _engine(args)
    reports = fuzz(eng.rules, eng, rounds=args.rounds)
    worst = 1.0
    for rep in reports:
        print(f"\n{rep.rule_id}")
        for name in rep.per_mutator:
            d, t = rep.per_mutator[name]
            rec = rep.recall(name)
            worst = min(worst, rec)
            bar = "#" * int(rec * 20)
            print(f"  {name:18s} {d:3d}/{t:<3d} {rec:6.0%} {bar}")
    return 0 if worst >= args.min_recall else 1


def cmd_eval(args) -> int:
    eng = _engine(args)

    def show(v) -> None:
        print(json.dumps(v.to_dict()) if args.json else v.explain())

    last_ts = None
    for raw in read_jsonl(args.events):
        raw.pop("labels", None)
        ev = Event(**raw)
        for v in eng.advance_time(ev.ts):
            show(v)
        show(eng.evaluate(ev))
        last_ts = ev.ts
    if last_ts is not None:
        for v in eng.advance_time(last_ts):
            show(v)
    return 0


def cmd_replay(args) -> int:
    eng = _engine(args)
    if args.baseline:
        eng.learn(Event(**r) for r in read_jsonl(args.baseline))
    report = replay(eng, read_jsonl(args.events))
    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2) + "\n")
    print(json.dumps(report.to_dict(), indent=2) if args.json else report.table(verbose=args.verbose))
    failures = report.failures(args.min_precision, args.min_recall)
    for f in failures:
        print(f"FAIL {f}", file=sys.stderr)
    return 1 if failures else 0


def cmd_import_sigma(args) -> int:
    print(yaml.safe_dump(sigma_to_chain(Path(args.file).read_text()), sort_keys=False))
    return 0


def cmd_import_yara(args) -> int:
    print(yaml.safe_dump_all(yara_to_chain(Path(args.file).read_text()), sort_keys=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="chain")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, *extra):
        sp = sub.add_parser(name)
        sp.set_defaults(fn=fn)
        if name.startswith("import"):
            sp.add_argument("file")
        else:
            sp.add_argument("rules")
            sp.add_argument("--clusters", default=str(DEFAULT_CLUSTERS))
        for a, kw in extra:
            sp.add_argument(a, **kw)
        return sp

    add("validate", cmd_validate)
    add("test", cmd_test)
    add("fuzz", cmd_fuzz, ("--rounds", {"type": int, "default": 3}), ("--min-recall", {"type": float, "default": 0.0}))
    add("eval", cmd_eval, ("events", {}), ("--json", {"action": "store_true"}))
    add("replay", cmd_replay, ("events", {}),
        ("--baseline", {"help": "JSONL of known-good history to seed rare: baselines"}),
        ("--min-precision", {"type": float, "default": 0.0}),
        ("--min-recall", {"type": float, "default": 0.0}),
        ("--out", {"help": "also write the JSON report here (for tracking over time)"}),
        ("--json", {"action": "store_true"}),
        ("-v", {"dest": "verbose", "action": "store_true", "help": "list FP / FN event ids"}))
    add("import-sigma", cmd_import_sigma)
    add("import-yara", cmd_import_yara)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
