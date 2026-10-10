# Chain — feature list

Status: **Built** = working in this scaffold with tests · **Stub** = interface + simple default, swap for production · **Planned** = designed, not built yet.

## 1. Unified event schema
| Feature | Status |
|---|---|
| One schema for files, processes, network, email, auth, logs and AI/agent events | Built |
| Trust level on every content span (untrusted / external / user / system) | Built |
| Provenance edges per event (`inputs` / `outputs` artifact ids) | Built |
| Free-form `fields` for Sigma-style log fields and sensor output | Built |
| Dotted-path field access (`tool.name`, `fields.beacon_score`) | Built |
| OCSF mapping / export | Planned |

## 2. Normalization (anti-evasion before matching)
| Feature | Status |
|---|---|
| Unicode NFKC, zero-width stripping, homoglyph folding | Built |
| Recursive decoding: base64, UTF-16 base64, hex, URL encoding | Built |
| PowerShell `-EncodedCommand` decoding | Built |
| cmd.exe caret de-obfuscation | Built |
| Full Unicode confusables table, string-concat / variable-substitution unrolling | Planned |
| Cross-document chunk reassembly | Planned |

## 3. Tiered matchers (run as a cost-ordered cascade)
| Feature | Status |
|---|---|
| Deterministic: regex, string sets, N-of-M (YARA `2 of them`) | Built |
| Semantic: similarity to attack clusters, per-sentence scoring so short payloads aren't diluted | Built (offline hashed embedder) |
| Pluggable real embedding model (`CHAIN_EMBEDDER=sentence-transformers:...`) | Built (optional dep) |
| Intent classifier per label (injection, exfiltration, destructive) | Stub (keyword model) |
| LLM judge with data-wrapping, JSON-only output, no tools | Built (bring your own model call) |
| Gray-zone escalation: judge runs only when cheaper tiers are uncertain | Built |
| `any` / `all` / nested trees, cheapest-first short-circuit | Built |
| FAISS / vector DB index for large clusters | Planned |
| Code / binary embeddings for malware family similarity | Planned |

## 4. Context
| Feature | Status |
|---|---|
| Taint propagation over artifact edges (email → file → process → network) | Built |
| Conservative context taint for agent sessions | Built |
| Attribution score (does tool output actually contain the tainted text?) | Built |
| `min_attribution` to require copy-through, not just context taint | Built |
| Per-entity baselines with `rare:` predicates ("first time on this host") | Built (in-memory) |
| `same:` field binding across steps (same host, same user) | Built |
| Trust-level predicates (`trust: {max: external}`) | Built |
| Intent vs. action rules (read-only task followed by external write) | Built (rule pattern) |
| Asset criticality / identity enrichment hooks | Planned |
| Time-decayed baselines in Redis per tenant | Planned |

## 5. Rule language
| Feature | Status |
|---|---|
| YAML rules, schema-validated on load | Built |
| Multi-step sequences with step and time windows | Built |
| `group_by` (session, host, user, any field) | Built |
| Event type globs (`ai.*`, `process.*`) | Built |
| Actions: allow / alert / redact / require_approval / block | Built |
| SOAR `response:` hints (isolate_host, kill_process_tree, open_case) | Built |
| Confidence scored from matcher evidence | Built |
| Absence / "not followed by" steps (`absent: true`, mid-sequence or final with `within`) | Built |
| Counting steps (`count: {min, within, distinct}`) | Built |

## 6. Verdicts and explainability
| Feature | Status |
|---|---|
| Strongest action wins across all firing rules | Built |
| Evidence trail per step: which event, which field, which matcher, which tier, taint path | Built |
| JSON output and human-readable `explain()` | Built |

## 7. Harness integration
| Feature | Status |
|---|---|
| `ChainGuard` hook points: prompt, retrieval, tool result, memory write, output | Built |
| `pre_tool_call` enforcement: raises `ToolBlocked` / `ApprovalRequired` | Built |
| `@guard.tool` decorator to wrap any tool | Built |
| Monitor-only mode (`enforce=False`) and verdict callback | Built |
| `guard.tick()` / `engine.advance_time()` for clock-confirmed absence verdicts | Built |
| Tool-to-event bridge: tool calls also evaluated as `process.start` / `net.flow` / `file.create` …, taint carried by a provenance edge | Built |
| `ai.detection` event after a corpus hit; bundled block / require_approval rules on it | Built |
| Platform stamping (`fields.platform`) and `when_set` predicate so platform-specific corpus rules scope themselves | Built |
| Async evaluation for alert-only rules | Planned |
| MCP proxy mode (Chain in front of any MCP server) | Planned |

## 8. Compatibility
| Feature | Status |
|---|---|
| Native Sigma evaluation: selections, keywords, modifiers (`contains`, `startswith`, `endswith`, `re`, `all`, `base64`, `windash`, `exists`, `cased`), `and/or/not`, `1 of x*`, `all of them` | Built |
| Sigma logsource → event type mapping (40 categories; unmapped ones scope to `<product>.<category>`) | Built |
| Importers report fidelity notes per rule (every dropped or approximated feature) | Built |
| YARA rules Chain can't run are **delegated** (kept with native source, matched on `fields.yara_matches`) | Built |
| `chain import-sigma` converter | Built |
| `chain import-yara` for text/regex strings with `any/all/N of them` | Built |
| Sigma modifiers `cidr`, `utf16*`, `base64offset`, `gt/lt`, `fieldref`, `expand`; Sigma aggregations and correlation rules | Planned (Phase B) |
| YARA hex strings, full conditions and modules in Chain's own matchers | Planned (Phase B; delegated meanwhile) |
| Suricata rule import | Planned |

## 8b. Sources and corpus (roadmap Phase A)
| Feature | Status |
|---|---|
| Source manifests (`sources/*.yaml`): git URL or local dir, pinned commit, format, paths, excludes, license, attribution | Built |
| `chain sources add / list / sync / status`; `--update` moves the pin, `--check-upstream` shows new commits | Built |
| Fetch by pinned commit into a local cache (shallow); local git repos pin too | Built |
| Pipeline: import → schema validation → safety checks → corpus write with `origin:` block | Built |
| Fidelity label per rule: `exact` / `lossy` (with notes) / `delegated` | Built |
| Safety checks: catastrophic regex (static + timed probes), matches-everything, unconstrained steps; `--strict` refuses them | Built |
| Sync report: counts, fidelity notes ranked by frequency (the Phase B priority list), failures, flags, added/updated/removed vs last sync | Built |
| `index.json` + `report.json` per source; corpus loads straight into `Engine.from_paths` | Built |
| Suricata source format | Planned (Phase B) |
| Corpus-wide dedup, quality scores, lifecycle states | Planned (Phase D) |

## 9. Testing and quality
| Feature | Status |
|---|---|
| Inline positive and negative test cases inside every rule | Built |
| Baseline seeding per test case | Built |
| Mutation fuzzing with recall per technique (zero-width, homoglyph, case, base64, URL, caret, burying in a long document) | Built |
| Pluggable LLM paraphrase mutator | Built (hook) |
| CI gate: `chain fuzz --min-recall 0.9` | Built |
| Replay against labeled historical data, precision/recall per rule (`chain replay`), CI gate | Built |
| Precision/recall dashboards over time | Planned (CI stores `replay-report.json` per run) |

## 10. CLI
`chain validate`, `chain test`, `chain fuzz`, `chain eval`, `chain replay`, `chain import-sigma`, `chain import-yara`, `chain sources add|list|sync|status` — all Built.
