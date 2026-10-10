# Chain roadmap

## Goal

Chain becomes the one place that holds the rules, signatures and IOCs that exist today in YARA, Sigma, Suricata and other sources, converted into one language, usable directly by LLMs and AI agents, and able to keep itself current.

It is three things:

| Part | What it is | Status |
|---|---|---|
| **Engine** | The rule language and runtime: sequences, taint, tiered matching, counting, absence, replay | Built (see [FEATURES.md](FEATURES.md)) |
| **Corpus** | Every rule, signature and IOC from every source, converted to Chain, with origin, license, fidelity and quality tracked per item | Phase A onward |
| **AI layer** | LLMs and agents search, run, explain and write rules; a gated loop improves the corpus over time | Phases E and F |

## Principles

1. **Every repo is a source.** A source is a small manifest (`sources/<name>.yaml`) naming the repo, the commit it is pinned to, its format, license and update schedule. Syncing a source produces a report: how many rules came in, how many converted exactly, how many lost something, how many failed, and which licenses apply.
2. **Fidelity is labelled, never assumed.** Every imported rule carries one of:
   - `exact` — Chain runs it with the same meaning as the original engine.
   - `lossy` — Chain runs it, but something was dropped. The label says what.
   - `delegated` — the original engine (yara-python, Suricata) runs it as a sensor; Chain does correlation, context and the AI layer on top.

   "Replace YARA, Sigma and Suricata" means one place to write, search, test and manage rules, not one matching engine for everything. Suricata stays the packet sensor.
3. **Self-evolving always works through gates.** Any rule change, from a human or an LLM, passes tests, fuzzing and replay first, then runs in shadow mode before it can alert. Nothing is promoted to blocking automatically.
4. **Licenses are respected.** Sources carry different licenses (Sigma DRL, GPL YARA sets, ET Open vs ET Pro). The public repo holds manifests and converters; the corpus is built locally or per customer, and every corpus item records its license.

## Phases

### Done — Engine core and Phase 1

Unified event schema, normalization, tiered matchers, provenance and taint, sequences, `ChainGuard`, Sigma/YARA importers, inline tests, fuzzing, counting, "not followed by", `chain replay` with precision and recall per rule.

### Phase A — Source registry and ingestion ✅

- `sources/*.yaml` manifests; `chain sources add <git-url>`, `chain sources sync`, `chain sources status`.
- Pipeline: fetch the pinned commit → detect format → import → validate → safety checks → test → write to corpus → report what changed.
- Every corpus rule records origin, upstream id and path, pinned commit, license, fidelity label and notes, ATT&CK / ATLAS tags, required log source.
- Safety checks on everything imported: catastrophic regex backtracking, rules that match everything, conversion errors. A bad upstream rule never reaches production unchecked.
- Starts with SigmaHQ, since the importer already exists.

**Done when:** `chain sources sync sigmahq` builds a corpus from a pinned SigmaHQ commit with a per-rule fidelity label and a report, and the corpus loads in the engine.

**Result:** 3,768 SigmaHQ rules, 3,750 exact, 18 lossy, 0 failed, 7 safety-flagged, in 17 s. Remaining lossy modifiers (`base64offset`, `fieldref`, `expand`, `wide`, regex flags) go to Phase B.

### Phase B — Full coverage of the three formats

- **Sigma:** counting rules (`| count() > n`), correlation rules (map onto Chain sequences), log source and field mapping onto Chain's schema.
- **YARA:** hex strings, wildcards, jumps, full conditions. Modules (pe, elf, math …) delegated to yara-python.
- **Suricata:** rule parser and mapping onto network events with protocol fields. Packet matching delegated to Suricata.
- **Differential testing:** the original engine and the Chain conversion run on the same samples; every mismatch is reported and lowers the fidelity label.

### Phase C — IOC and threat intel layer

- IOC store: hashes, IPs, domains, URLs, JA3/JA4, certificates, each with confidence, first/last seen and expiry.
- Feed connectors: STIX/TAXII, MISP, CSV and JSON feeds.
- `ioc:` predicate for rules (`where: {fields.dest_ip: {ioc: c2}}`) backed by fast set lookups, not one rule per IOC.
- IOCs linked to campaigns, techniques and the rules that use them.

### Phase D — Unification and quality

- Find equivalent rules across sources; merge into one canonical rule with aliases.
- Quality score per rule from tests, replay precision, false-positive history and upstream upkeep.
- Coverage map against ATT&CK and ATLAS: what is covered, by which rules, and the gaps.
- Rule lifecycle: draft → shadow → alert → enforce. Versioned corpus releases as rule packs.

### Phase E — Ready for LLMs and agents

- A rule card per rule: what it detects, example events, known false positives, data it needs.
- Published JSON Schema for the rule language, so LLMs write valid rules first time.
- Semantic search over the whole corpus.
- MCP server: `search_rules`, `evaluate_event`, `check_ioc`, `explain_verdict`, `propose_rule`; proxy mode in front of other MCP servers.
- Integrations for common agent frameworks, built on `ChainGuard`.

### Phase F — Self-evolving and self-healing

- Health monitoring flags rules that never fire, false-positive spikes, upstream changes that broke an import, log formats that drifted, and fuzz techniques that now evade a rule.
- Repair loop: an LLM proposes a fix → tests, fuzzing and replay → human approval → shadow mode → promotion.
- Rule generation from new intel, from misses in replay, and from evasions the fuzzer finds, through the same gates.
- Every change is a git commit carrying its evidence; every change can be rolled back.

### Phase G — Production scale

- Pluggable state store with Redis; each customer's data kept separate; taint and sequence state expire.
- Time-decayed baselines. Asset and identity enrichment hooks.
- Hot reload of rule packs without restart. Background evaluation for alert-only rules.
- Latency benchmarks; Rust / Hyperscan for the hot path if needed.

## Order

```
A ──► B ──┐
A ──► C ──┼──► D ──► E ──► F
          │
G (any time; required before production)
```

A first. B and C both build on A and can run in parallel. D needs B and C. E's MCP server can start early, but rule cards and search need D. F needs D's lifecycle states and E's LLM tooling. G can run alongside anything and must be done before production.

## Open decisions

| Question | Current default |
|---|---|
| Corpus location | Built into `corpus/` locally (gitignored); manifests and converters are what the repo ships |
| How far Suricata goes | Delegated: Suricata stays the packet sensor, Chain owns the rules and logic on top |
| Autonomy in Phase F | The system proposes; humans approve anything beyond shadow mode |
| "Skills" repositories | To be classified when shared: agent skills, technique knowledge (ATT&CK, ATLAS, OWASP LLM Top 10) or rule sets decide whether they feed A, D or E |
