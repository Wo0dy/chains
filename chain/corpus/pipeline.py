"""Sync pipeline: upstream repo at a pinned commit -> validated Chain rules in the corpus.

For each rule file:  read -> detect format -> import (with fidelity notes)
                     -> validate (schema) -> safety checks -> write with origin

Output per source, under <corpus>/<source>/:
    <upstream path>.yaml     one Chain rule per file, with an `origin:` block
    index.json               id -> path, fidelity, upstream hash  (used to diff the next sync)
    report.json              the full SyncReport of the last sync
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import shutil
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..importers.sigma import SigmaUnsupported, sigma_import, sigma_import_correlation
from ..importers.suricata import link_flowbits, suricata_import
from ..importers.yara import YaraContext, yara_import
from ..yara import parse_file as parse_yara_file
from ..rules import Origin, load_rule
from .safety import check_rule
from .sources import DEFAULT_CACHE_DIR, DEFAULT_CORPUS_DIR, Source, fetch, now, resolve_head, save_source

YAML_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
YAML_DUMPER = getattr(yaml, "CSafeDumper", yaml.SafeDumper)
SIGMA_EXT = {".yml", ".yaml"}
YARA_EXT = {".yar", ".yara"}
SURICATA_EXT = {".rules"}
SKIP_DIRS = {".git", ".github", "tests", "test", "deprecated", "unsupported"}


@dataclass
class Item:
    path: str                       # upstream path (posix, relative to the repo root)
    outcome: str                    # imported | failed | skipped
    rule_id: str | None = None
    corpus_path: str | None = None
    fidelity: str | None = None     # exact | lossy | delegated
    notes: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)   # safety flags
    reason: str | None = None       # why failed / skipped
    change: str | None = None       # added | updated | unchanged
    deferred: Any = field(default=None, repr=False, compare=False)   # correlation doc awaiting its base rules


@dataclass
class SyncReport:
    source: str
    ref: str
    started: str
    files: int = 0
    items: list[Item] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)   # rule ids gone since the previous sync
    license: str = ""
    strict: bool = False

    # ---- counts
    def _count(self, **match: Any) -> int:
        return sum(all(getattr(i, k) == v for k, v in match.items()) for i in self.items)

    @property
    def imported(self) -> int:
        return self._count(outcome="imported")

    @property
    def failed(self) -> int:
        return self._count(outcome="failed")

    @property
    def skipped(self) -> int:
        return self._count(outcome="skipped")

    @property
    def flagged(self) -> int:
        return sum(1 for i in self.items if i.flags and i.outcome == "imported")

    def by_fidelity(self) -> dict[str, int]:
        return {f: self._count(outcome="imported", fidelity=f) for f in ("exact", "lossy", "delegated")}

    def note_counts(self) -> list[tuple[str, int]]:
        """Most common fidelity notes: this is the Phase B priority list."""
        c: Counter[str] = Counter()
        for i in self.items:
            for n in set(_generalize(n) for n in i.notes):
                c[n] += 1
        return c.most_common()

    def reason_counts(self) -> list[tuple[str, int]]:
        c: Counter[str] = Counter(_generalize(i.reason or "") for i in self.items if i.outcome == "failed")
        return c.most_common()

    def flag_counts(self) -> list[tuple[str, int]]:
        c: Counter[str] = Counter()
        for i in self.items:
            for f in set(_generalize(f) for f in i.flags):
                c[f] += 1
        return c.most_common()

    def changes(self) -> dict[str, int]:
        return {k: self._count(outcome="imported", change=k) for k in ("added", "updated", "unchanged")} | \
            {"removed": len(self.removed)}

    @property
    def ok(self) -> bool:
        if self.strict:
            return self.failed == 0 and self.flagged == 0
        return True

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for i in d["items"]:
            i.pop("deferred", None)
        d.update(summary={"imported": self.imported, "failed": self.failed, "skipped": self.skipped,
                          "flagged": self.flagged, "fidelity": self.by_fidelity(), "changes": self.changes()},
                 notes=self.note_counts(), reasons=self.reason_counts(), flags=self.flag_counts())
        return d

    def table(self, verbose: bool = False) -> str:
        fid = self.by_fidelity()
        ch = self.changes()
        lines = [
            f"{self.source} @ {self.ref[:12] or 'local'}  license: {self.license or 'unspecified'}",
            f"  files {self.files}  imported {self.imported} (exact {fid['exact']}, lossy {fid['lossy']}, "
            f"delegated {fid['delegated']})  failed {self.failed}  skipped {self.skipped}  flagged {self.flagged}",
            f"  changes: +{ch['added']} ~{ch['updated']} ={ch['unchanged']} -{ch['removed']}",
        ]
        if self.note_counts():
            lines.append("  fidelity notes (what Chain approximates; fix these to raise exact count):")
            lines += [f"    {n:5d}  {text}" for text, n in self.note_counts()[:15]]
        if self.reason_counts():
            lines.append("  failures:")
            lines += [f"    {n:5d}  {text}" for text, n in self.reason_counts()[:15]]
        if self.flag_counts():
            lines.append("  safety flags:")
            lines += [f"    {n:5d}  {text}" for text, n in self.flag_counts()[:15]]
        if verbose:
            for i in self.items:
                if i.outcome == "failed":
                    lines.append(f"  FAIL  {i.path}: {i.reason}")
                for f in i.flags:
                    lines.append(f"  FLAG  {i.path}: {f}")
        return "\n".join(lines)


def _generalize(text: str) -> str:
    """Collapse per-rule specifics so notes group: field names, numbers, quoted values."""
    text = re.sub(r"\(field [^)]*\)", "", text)
    text = re.sub(r"(escaped wildcard|invalid regex) in \S+", r"\1 in <field>", text)
    text = re.sub(r"category '[^']*'", "category '<x>'", text)
    text = re.sub(r"using \S+", "", text)
    text = re.sub(r"regex at \S+:", "regex:", text)
    text = re.sub(r"\d+-char", "N-char", text)
    text = re.sub(r"condition ['\"].*", "condition '<x>'", text, flags=re.S)
    return " ".join(text.split())


# ------------------------------------------------------------------ discovery
def _detect_format(path: Path, declared: str) -> str | None:
    ext = path.suffix.lower()
    if declared == "sigma":
        return "sigma" if ext in SIGMA_EXT else None
    if declared == "yara":
        return "yara" if ext in YARA_EXT else None
    if declared == "chain":
        return "chain" if ext in SIGMA_EXT else None
    if declared == "suricata":
        return "suricata" if ext in SURICATA_EXT else None
    if ext in SURICATA_EXT:
        return "suricata"
    if ext in YARA_EXT:
        return "yara"
    if ext in SIGMA_EXT:
        return "sigma"
    return None


def _files(root: Path, src: Source) -> list[Path]:
    out: list[Path] = []
    for rel in src.paths:
        base = (root / rel).resolve()
        if not base.exists():
            continue
        for p in sorted(base.rglob("*")):
            if not p.is_file():
                continue
            relp = p.relative_to(root).as_posix()
            if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
                continue
            if any(fnmatch.fnmatch(relp, pat) or fnmatch.fnmatch(relp, pat.rstrip("/") + "/*") for pat in src.exclude):
                continue
            if _detect_format(p, src.format):
                out.append(p)
    return out


# ------------------------------------------------------------------ one file
def _origin(src: Source, relp: str, text: str, **kw: Any) -> dict[str, Any]:
    o = Origin(source=src.name, format=kw.pop("format"), path=relp, ref=src.ref,
               upstream_sha256=hashlib.sha256(text.encode()).hexdigest(), license=src.license, **kw)
    # keep the YAML readable: drop empty optional fields, keep `notes` so flags can append to it
    return {k: v for k, v in o.model_dump().items() if v not in (None, "", [], {}) or k in ("notes", "ref")}


def _import_file(src: Source, root: Path, path: Path, yara_rules: YaraContext | None = None) -> list[tuple[Item, dict[str, Any] | None]]:
    relp = path.relative_to(root).as_posix()
    fmt = _detect_format(path, src.format)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        return [(Item(relp, "failed", reason=f"not utf-8: {e}"), None)]

    if fmt == "sigma":
        return [_import_sigma(src, relp, text)]
    if fmt == "yara":
        return _import_yara(src, relp, text, yara_rules)
    if fmt == "suricata":
        return _import_suricata(src, relp, text)
    if fmt == "chain":
        return [_import_chain(src, relp, text)]
    return [(Item(relp, "skipped", reason="unknown format"), None)]


def _sigma_origin(src: Source, relp: str, text: str, imp: Any) -> dict[str, Any]:
    return _origin(src, relp, text, format="sigma", upstream_id=imp.meta["upstream_id"],
                   upstream_name=imp.meta.get("name"), fidelity="lossy" if imp.notes else "exact",
                   notes=list(imp.notes), status=imp.meta.get("status"), logsource=imp.meta["logsource"],
                   falsepositives=[str(x) for x in imp.meta["falsepositives"]],
                   references=[str(x) for x in imp.meta["references"]])


def _import_sigma(src: Source, relp: str, text: str) -> tuple[Item, dict[str, Any] | None]:
    try:
        docs = [d for d in yaml.load_all(text, Loader=YAML_LOADER) if d]
        if len(docs) != 1:
            raise SigmaUnsupported("multi-document rule collection")
        if isinstance(docs[0], dict) and "correlation" in docs[0]:
            # needs the rules it references: resolved after the first pass
            return Item(relp, "deferred", deferred=docs[0]), None
        imp = sigma_import(docs[0])
    except SigmaUnsupported as e:
        return Item(relp, "failed", reason=f"unsupported: {e}"), None
    except yaml.YAMLError as e:
        return Item(relp, "failed", reason=f"yaml: {str(e).splitlines()[0]}"), None
    except (KeyError, TypeError, AttributeError) as e:
        return Item(relp, "failed", reason=f"malformed rule: {type(e).__name__}: {e}"), None
    status = imp.meta.get("status")
    if status in src.skip_status:
        return Item(relp, "skipped", rule_id=imp.rule["id"], reason=f"status {status}"), None
    rule = dict(imp.rule)
    rule["origin"] = _sigma_origin(src, relp, text, imp)
    return Item(relp, "imported", rule_id=rule["id"], fidelity=rule["origin"]["fidelity"], notes=list(imp.notes)), rule


def _import_correlation(src: Source, relp: str, doc: dict[str, Any], lookup: dict[str, dict[str, Any]]) -> tuple[Item, dict[str, Any] | None]:
    try:
        imp = sigma_import_correlation(doc, lookup.get)
    except SigmaUnsupported as e:
        return Item(relp, "failed", reason=f"unsupported: {e}"), None
    except (KeyError, TypeError, AttributeError, ValueError) as e:
        return Item(relp, "failed", reason=f"malformed correlation: {type(e).__name__}: {e}"), None
    status = imp.meta.get("status")
    if status in src.skip_status:
        return Item(relp, "skipped", rule_id=imp.rule["id"], reason=f"status {status}"), None
    rule = dict(imp.rule)
    text = yaml.safe_dump(doc, sort_keys=False)
    rule["origin"] = _sigma_origin(src, relp, text, imp)
    return Item(relp, "imported", rule_id=rule["id"], fidelity=rule["origin"]["fidelity"], notes=list(imp.notes)), rule


def _all_yara_rules(root: Path, files: list[Path]) -> YaraContext:
    """Every YARA rule in the source, by name, so cross-file references resolve."""
    ctx = YaraContext()
    for p in files:
        if p.suffix.lower() not in YARA_EXT:
            continue
        try:
            for r in parse_yara_file(p.read_text(encoding="utf-8", errors="replace"))[0]:
                ctx.add(r)
        except Exception:  # noqa: BLE001 - reported when the file itself is imported
            continue
    return ctx


def _import_yara(src: Source, relp: str, text: str, extra: YaraContext | None = None) -> list[tuple[Item, dict[str, Any] | None]]:
    try:
        imports = yara_import(text, extra)
    except Exception as e:  # noqa: BLE001
        return [(Item(relp, "failed", reason=f"parse: {type(e).__name__}: {str(e).splitlines()[0]}"), None)]
    if not imports:
        return [(Item(relp, "skipped", reason="no rules in file (commented out?)"), None)]
    out = []
    for imp in imports:
        rule = dict(imp.rule)
        fid = "delegated" if imp.delegated else "exact"
        rule["origin"] = _origin(src, relp, text, format="yara", upstream_id=imp.name, fidelity=fid,
                                 notes=list(imp.notes), native=imp.source if imp.delegated else None)
        out.append((Item(f"{relp}#{imp.name}", "imported", rule_id=rule["id"], fidelity=fid, notes=list(imp.notes)), rule))
    return out


def _import_suricata(src: Source, relp: str, text: str) -> list[tuple[Item, dict[str, Any] | None]]:
    try:
        imports = suricata_import(text, src.variables or None)
    except Exception as e:  # noqa: BLE001
        return [(Item(relp, "failed", reason=f"parse: {type(e).__name__}: {str(e).splitlines()[0]}"), None)]
    if not imports:
        return [(Item(relp, "skipped", reason="no enabled rules in file"), None)]
    link_flowbits(imports)
    out = []
    for imp in imports:
        if not imp.rule:
            out.append((Item(f"{relp}#line{imp.meta.get('line', '?')}", "failed", reason=imp.notes[0]), None))
            continue
        rule = dict(imp.rule)
        fid = "delegated" if imp.delegated else ("lossy" if imp.notes else "exact")
        rule["origin"] = _origin(src, relp, text, format="suricata", upstream_id=imp.sid, fidelity=fid,
                                 notes=list(imp.notes), native=imp.source if imp.delegated else None,
                                 references=[str(x) for x in imp.meta.get("references", []) if x])
        out.append((Item(f"{relp}#{imp.sid}", "imported", rule_id=rule["id"], fidelity=fid, notes=list(imp.notes)), rule))
    return out


def _import_chain(src: Source, relp: str, text: str) -> tuple[Item, dict[str, Any] | None]:
    try:
        docs = [d for d in yaml.load_all(text, Loader=YAML_LOADER) if d]
    except yaml.YAMLError as e:
        return Item(relp, "failed", reason=f"yaml: {str(e).splitlines()[0]}"), None
    if len(docs) != 1 or "sequence" not in docs[0]:
        return Item(relp, "failed", reason="not a single Chain rule"), None
    rule = dict(docs[0])
    rule["origin"] = _origin(src, relp, text, format="chain", upstream_id=str(rule.get("id", "")), fidelity="exact")
    return Item(relp, "imported", rule_id=rule.get("id"), fidelity="exact"), rule


def _corpus_path(item: Item) -> str:
    base = item.path
    if "#" in base:                                   # one YARA / Suricata file, many rules
        file, name = base.split("#", 1)
        return f"{Path(file).with_suffix('')}/{name}.yaml"
    return str(Path(base).with_suffix(".yaml"))


# ------------------------------------------------------------------ sync
def sync_source(src: Source, corpus_dir: Path = DEFAULT_CORPUS_DIR, cache_dir: Path = DEFAULT_CACHE_DIR,
                strict: bool = False, update: bool = False, sources_dir: Path | None = None) -> SyncReport:
    if update and src.ref:   # pinned sources only; a plain local directory has nothing to move
        src.ref = resolve_head(src.url, src.branch)
    root = fetch(src, cache_dir)
    report = SyncReport(src.name, src.ref, now(), license=src.license, strict=strict)
    out_dir = Path(corpus_dir) / src.name
    previous = _read_index(out_dir)

    files = _files(root, src)
    report.files = len(files)
    seen_ids: dict[str, str] = {}
    written: dict[str, dict[str, Any]] = {}

    def accept(item: Item, rule: dict[str, Any] | None) -> None:
        if rule is not None:
            try:
                compiled = load_rule(rule, item.path)
            except Exception as e:  # noqa: BLE001 - any schema problem is a failed import
                item.outcome, item.reason, rule = "failed", f"schema: {str(e).splitlines()[0]}", None
            else:
                if compiled.id in seen_ids:
                    item.outcome, item.reason, rule = "failed", f"duplicate id (also {seen_ids[compiled.id]})", None
                else:
                    seen_ids[compiled.id] = item.path
                    item.flags = check_rule(compiled)
                    if item.flags:
                        rule["origin"]["notes"] = rule["origin"]["notes"] + [f"safety: {f}" for f in item.flags]
                        if strict:
                            item.outcome, item.reason, rule = "failed", f"strict: {item.flags[0]}", None
        if rule is not None:
            item.corpus_path = _corpus_path(item)
            prev = previous.get(item.rule_id or "")
            if prev is None:
                item.change = "added"
            elif prev.get("upstream_sha256") == rule["origin"]["upstream_sha256"] and prev.get("path") == item.corpus_path:
                item.change = "unchanged"
            else:
                item.change = "updated"
            written[item.corpus_path] = rule
        report.items.append(item)

    deferred: list[Item] = []
    yara_rules = _all_yara_rules(root, files) if any(p.suffix.lower() in YARA_EXT for p in files) else None
    for path in files:
        for item, rule in _import_file(src, root, path, yara_rules):
            if item.outcome == "deferred":
                deferred.append(item)
            else:
                accept(item, rule)

    if deferred:
        # Second pass: correlation rules reference base rules by name or id.
        lookup: dict[str, dict[str, Any]] = {}
        for rule in written.values():
            o = rule.get("origin", {})
            for key in (rule.get("id"), o.get("upstream_id"), o.get("upstream_name")):
                if key:
                    lookup.setdefault(str(key), rule)
        for item in deferred:
            doc, item.deferred = item.deferred, None
            accept(*_import_correlation(src, item.path, doc, lookup))

    report.removed = sorted(set(previous) - set(seen_ids))
    _write_corpus(out_dir, written, report)
    src.last_sync, src.last_sync_ref = report.started, src.ref
    if sources_dir is not None:
        save_source(src, sources_dir)
    return report


def _read_index(out_dir: Path) -> dict[str, dict[str, Any]]:
    p = out_dir / "index.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text()).get("rules", {})


def _write_corpus(out_dir: Path, written: dict[str, dict[str, Any]], report: SyncReport) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    index: dict[str, Any] = {}
    for rel, rule in written.items():
        p = out_dir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(yaml.dump(rule, Dumper=YAML_DUMPER, sort_keys=False, allow_unicode=True, width=120))
        o = rule["origin"]
        index[rule["id"]] = {"path": rel, "fidelity": o["fidelity"], "upstream_sha256": o["upstream_sha256"],
                             "upstream_path": o["path"], "status": o.get("status"), "severity": rule.get("severity"),
                             "title": rule.get("title", ""), "tags": rule.get("tags", []), "flags": bool(o["notes"] and
                             any(n.startswith("safety:") for n in o["notes"]))}
    (out_dir / "index.json").write_text(json.dumps(
        {"source": report.source, "ref": report.ref, "synced": report.started, "license": report.license,
         "rules": index}, indent=1, sort_keys=True))
    (out_dir / "report.json").write_text(json.dumps(report.to_dict(), indent=1))


def corpus_status(corpus_dir: Path, name: str) -> dict[str, Any] | None:
    p = Path(corpus_dir) / name / "index.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    rules = data.get("rules", {})
    fid = Counter(r["fidelity"] for r in rules.values())
    return {"synced": data.get("synced"), "ref": data.get("ref"), "rules": len(rules),
            "exact": fid["exact"], "lossy": fid["lossy"], "delegated": fid["delegated"],
            "flagged": sum(1 for r in rules.values() if r.get("flags"))}
