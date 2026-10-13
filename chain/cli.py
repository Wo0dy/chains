"""chain CLI

  chain validate RULES            compile rules, report errors
  chain test RULES                run inline rule tests
  chain fuzz RULES                mutation-fuzz positive tests, report recall per technique
  chain eval RULES EVENTS.jsonl   run events through the engine, print verdicts
  chain replay RULES LABELED.jsonl  score rules against labeled history (precision / recall)
  chain import-sigma FILE         convert a Sigma rule to Chain YAML
  chain import-yara FILE          convert simple YARA rules to Chain YAML
  chain sources add URL           register an upstream rule repo, pinned to its current head
  chain sources list              show registered sources
  chain sources sync [NAME ...]   pull pinned commits, convert, check and write the corpus
  chain sources status            corpus counts per source; --check-upstream shows new commits
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from .corpus.pipeline import corpus_status, sync_source
from .corpus.sources import (DEFAULT_CACHE_DIR, DEFAULT_CORPUS_DIR, DEFAULT_SOURCES_DIR, add_source, list_sources,
                             load_source, resolve_head)
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


# ------------------------------------------------------------------ sources
def cmd_sources_add(args) -> int:
    fields = {k: v for k, v in dict(format=args.format, paths=args.paths, exclude=args.exclude, license=args.license,
                                     attribution=args.attribution, branch=args.branch, ref=args.ref,
                                     description=args.description).items() if v}
    src = add_source(args.url, args.name, Path(args.sources), **fields)
    print(f"added {src.name}: {src.url} @ {src.ref[:12] or 'local'} -> {src.manifest_path(Path(args.sources))}")
    return 0


def cmd_sources_list(args) -> int:
    sources = list_sources(Path(args.sources))
    if not sources:
        print(f"no sources in {args.sources}")
        return 0
    for s in sources:
        print(f"{s.name:20s} {s.format:6s} {s.ref[:12] or 'local':12s} {s.url}  paths={','.join(s.paths)}"
              f"  license={s.license or '-'}  last_sync={s.last_sync or 'never'}")
    return 0


def cmd_sources_sync(args) -> int:
    names = args.names or [s.name for s in list_sources(Path(args.sources))]
    if not names:
        print(f"no sources in {args.sources}; add one with `chain sources add URL`")
        return 1
    rc = 0
    reports = []
    for name in names:
        src = load_source(name, Path(args.sources))
        rep = sync_source(src, Path(args.corpus), Path(args.cache), strict=args.strict, update=args.update,
                          sources_dir=Path(args.sources))
        reports.append(rep)
        if not args.json:
            print(rep.table(verbose=args.verbose))
            print()
        if not rep.ok:
            rc = 1
    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=1))
    return rc


def cmd_sources_status(args) -> int:
    sources = list_sources(Path(args.sources))
    if not sources:
        print(f"no sources in {args.sources}")
        return 0
    print(f"{'source':20s} {'pinned':12s} {'rules':>6s} {'exact':>6s} {'lossy':>6s} {'deleg':>6s} {'flags':>6s}  synced")
    for s in sources:
        st = corpus_status(Path(args.corpus), s.name)
        if st is None:
            line = f"{s.name:20s} {s.ref[:12] or 'local':12s} {'-':>6s} {'-':>6s} {'-':>6s} {'-':>6s} {'-':>6s}  never"
        else:
            line = (f"{s.name:20s} {s.ref[:12] or 'local':12s} {st['rules']:6d} {st['exact']:6d} {st['lossy']:6d} "
                    f"{st['delegated']:6d} {st['flagged']:6d}  {st['synced']}")
            if st["ref"] != s.ref:
                line += "  (corpus is from a different commit; re-sync)"
        if args.check_upstream and not s.is_local:
            try:
                head = resolve_head(s.url, s.branch)
                line += "  upstream: up to date" if head == s.ref else f"  upstream: new commit {head[:12]} (sync --update)"
            except RuntimeError as e:
                line += f"  upstream: {e}"
        print(line)
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

    src = sub.add_parser("sources", help="manage upstream rule sources and the corpus")
    ssub = src.add_subparsers(dest="scmd", required=True)

    def add_src(name, fn, *extra):
        sp = ssub.add_parser(name)
        sp.set_defaults(fn=fn)
        sp.add_argument("--sources", default=str(DEFAULT_SOURCES_DIR), help="manifest directory")
        sp.add_argument("--corpus", default=str(DEFAULT_CORPUS_DIR), help="corpus output directory")
        sp.add_argument("--cache", default=str(DEFAULT_CACHE_DIR), help="where upstream checkouts are kept")
        for a, kw in extra:
            sp.add_argument(a, **kw)
        return sp

    add_src("add", cmd_sources_add, ("url", {}), ("--name", {}), ("--format", {"choices": ["auto", "sigma", "yara", "suricata", "chain"]}),
            ("--paths", {"nargs": "+"}), ("--exclude", {"nargs": "+"}), ("--license", {}), ("--attribution", {}),
            ("--branch", {}), ("--ref", {"help": "pin to this commit instead of the branch head"}), ("--description", {}))
    add_src("list", cmd_sources_list)
    add_src("sync", cmd_sources_sync, ("names", {"nargs": "*"}),
            ("--update", {"action": "store_true", "help": "move the pin to the newest upstream commit first"}),
            ("--strict", {"action": "store_true", "help": "exit 1 if any rule failed or was flagged"}),
            ("--json", {"action": "store_true"}), ("-v", {"dest": "verbose", "action": "store_true"}))
    add_src("status", cmd_sources_status, ("--check-upstream", {"action": "store_true"}))

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
