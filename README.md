<p align="center">
  <img src="assets/logo.svg" alt="Chain logo" width="160">
</p>

<h1 align="center">Chain</h1>

<p align="center">
  <b>Detection rules that understand meaning, provenance and sequence — for classic SecOps and AI agents.</b>
</p>

<p align="center">
  <a href="https://github.com/wo0dy/chains/actions/workflows/ci.yml"><img src="https://github.com/wo0dy/chains/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-3776AB" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-6366F1" alt="MIT license">
</p>

---

Chain is a detection language and engine. It does what YARA, Sigma and Suricata rules do, then adds what they can't:

- **Meaning, not just strings.** Content is decoded and normalized before matching, then checked by a cost-ordered cascade: regex → semantic similarity → classifier → LLM judge. Paraphrased or obfuscated attacks still match.
- **Provenance and taint.** Every event records what it read and what it produced. A rule can require that a process *descends from* a phishing attachment, or that an agent's tool call happens *after untrusted content entered its context*.
- **Multi-step sequences.** One rule can describe a whole attack chain across events, hosts and domains, with time and step windows, counting ("5 failures in 5 minutes") and absence ("login *not followed by* MFA").
- **Baselines.** `rare:` predicates catch "first time this tool ran on this host".
- **Inline enforcement for agents.** `ChainGuard` sits inside an agent harness and can block a tool call or require human approval before it runs.
- **Evidence, not just scores.** Every verdict lists the events, fields, matchers, tiers and taint path that produced it.

## Contents

- [Architecture](#architecture)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Writing rules](#writing-rules)
- [Event schema](#event-schema)
- [Using Chain inside an agent harness](#using-chain-inside-an-agent-harness)
- [Importing Sigma and YARA](#importing-sigma-and-yara)
- [Testing and fuzzing rules](#testing-and-fuzzing-rules)
- [Measuring rules on labeled data](#measuring-rules-on-labeled-data)
- [CLI reference](#cli-reference)
- [Project layout](#project-layout)
- [Feature status](#feature-status)
- [Roadmap](#roadmap)
- [Production swaps](#production-swaps)
- [Design notes](#design-notes)

## Architecture

Chain is a rule repository and a live detection runtime in one. Rules and attack clusters are versioned content, CI gates every change, and the engine evaluates each event against state that keeps changing: in-flight sequences, baselines, taint and the semantic index.

```mermaid
flowchart TB
    subgraph content["Detection content (versioned in git)"]
        direction LR
        rules["rules/<br/>YAML sequences + inline tests"]
        clusters["clusters/<br/>attack example sets"]
        importers["importers/<br/>Sigma, YARA → rule YAML"]
        importers --> rules
    end

    subgraph gates["Quality gates (CI)"]
        direction LR
        validate[validate] --> test[test] --> fuzz["fuzz<br/>recall ≥ 0.9"] --> replay["replay<br/>precision / recall ≥ 0.9<br/>on labeled verdicts"]
    end

    subgraph sources["Sources → one Event schema"]
        classic["Classic telemetry<br/>EDR · auth · email · net · logs"]
        batch["Batch<br/>chain eval · chain replay"]
        harness["AI agent harness<br/>ChainGuard hooks"]
    end

    subgraph engine["Runtime engine"]
        direction LR
        normalize[Normalize] --> provenance["Provenance<br/>& taint"] --> sequences["Sequences<br/>where · same · rare<br/>count · absent"] --> verdict["Verdict<br/>strongest action wins"]
        sequences <-.->|"match / score"| cascade
        subgraph cascade["Content cascade, cheapest first"]
            direction LR
            regex["regex · strings"] -.-> semantic -.-> classifier -.-> judge["LLM judge<br/>gray band only"]
        end
        subgraph state["Live state (read during match, written after)"]
            direction LR
            seqstate[sequence state] ~~~ baselines ~~~ taint[taint graph] ~~~ index[semantic index]
        end
    end

    subgraph outcomes["Outcomes"]
        stream["Verdict stream<br/>action · SOAR hints · evidence"]
        deferred["Deferred verdicts<br/>tick() / advance_time()"]
        enforce["Inline enforcement<br/>ToolBlocked · ApprovalRequired<br/>raised to the agent before the tool runs"]
    end

    content -->|PR| gates
    gates -->|compiled rule pack| engine
    sources -->|events| engine
    engine -->|verdicts| outcomes
```

Dotted arrows mark the escalating content cascade: a costlier tier runs only when a cheaper one is uncertain. The loop closes outside the runtime: triaged verdicts become labeled events, `chain replay` scores every rule against them, and the false positives and misses it reports drive the next rule fix or cluster update. Live state is in-memory today; Redis per tenant and FAISS are the planned swaps.

## How it works

```mermaid
flowchart LR
    S[Sensors / logs / agent hooks] --> E[Event]
    E --> P[Provenance & taint]
    P --> R{For each rule:<br/>advance sequences}
    R --> C1[event type] --> C2[where / rare] --> C3[same] --> C4[tainted_by] --> C5[content cascade]
    C5 --> H[Hits]
    H --> V[Verdict:<br/>strongest action wins]
    V --> A[allow · alert · redact ·<br/>require_approval · block]
```

For each event, the engine:

1. Records provenance: artifact edges (`inputs` / `outputs`) and, for agent sessions, context taint.
2. Advances every rule's in-flight sequences for the event's group (session, host, user …).
3. Runs step checks cheapest-first: event type → `where` fields → `same` binding → taint → content matchers.
4. Turns completed sequences into hits. The strongest action across all hits becomes the verdict.
5. Updates baselines *after* evaluation, so an event never masks itself.

### The content cascade

| Tier | Matcher | Cost | What it catches |
|---|---|---|---|
| 1 | `regex`, `strings` (with `min: N` for YARA-style "N of them") | µs | Known indicators |
| 2 | `semantic` — cosine similarity to a cluster of attack examples, scored per sentence | ms | Paraphrases of known attacks |
| 3 | `classifier` — per-label probability (injection, exfiltration, destructive) | ms | Intent, not wording |
| 4 | `judge` / `escalate` — an LLM asked a yes/no question | 100s of ms | Gray-zone cases only |

Matchers are sorted by cost and short-circuit. The judge runs only when a cheaper tier lands in its uncertain "gray band".

### Normalization

Before any content matcher runs, text is expanded into a view containing the original plus every decoded layer:

- Unicode NFKC, zero-width character stripping, homoglyph folding (Cyrillic/Greek look-alikes)
- Recursive base64 (including UTF-16), hex and URL decoding
- PowerShell `-EncodedCommand` decoding
- cmd.exe caret removal (`p^o^w^e^r^s^h^e^l^l` → `powershell`)

A rule written against plain text therefore still fires on encoded or disguised variants. Use `on: raw` in a `match` block to match the original text instead.

## Quick start

Requires Python 3.10+.

```bash
git clone https://github.com/wo0dy/chains.git
cd chains
pip install -e ".[dev]"

chain validate rules                       # compile every rule
chain test rules                           # run inline rule tests
chain fuzz rules --min-recall 0.9          # adversarial mutations, recall per technique
chain eval rules examples/events.jsonl     # run sample events, print verdicts
chain replay rules examples/labeled_events.jsonl --baseline examples/baseline_events.jsonl
python examples/agent_harness_demo.py      # ChainGuard blocking an injected exfil
pytest -q
```

Example output from `chain eval`:

```
[e9499b2f5968] ALERT severity=critical
  rule classic_phish_to_ransomware (critical, conf 0.80, tiers -)
    step attach <- email.attachment 1933cf626ce9
      - trust='untrusted'
    step run <- file.exec 04a02232f75c
      - fields.signed=False
      - tainted by step attach (1933cf626ce9) via artifact:file:sha256:aa11; attribution 0.00
    step impact <- process.capability 5699919f8a89
      - fields.capabilities=['encrypt_bulk']
      - tainted by step attach (1933cf626ce9) via artifact:proc:4242; attribution 0.00
    step c2 <- net.flow e9499b2f5968
      - fields.beacon_score=0.91
      - tainted by step attach (1933cf626ce9) via artifact:proc:4242; attribution 0.00
```

Optional extras:

```bash
pip install -e ".[semantic]"   # sentence-transformers + faiss-cpu for real embeddings
pip install -e ".[yara]"       # yara-python, to run native YARA as a sensor
```

## Writing rules

Rules are YAML, validated on load. A rule is a sequence of one or more steps; a one-step rule is the equivalent of a Sigma or YARA rule.

### A classic attack chain

```yaml
id: classic_phish_to_ransomware
title: Phishing attachment leads to ransomware behavior and C2
severity: critical
action: alert
response: [isolate_host, kill_process_tree, open_case]   # SOAR hints
group_by: host
window: {seconds: 7200}
sequence:
  - name: attach
    event: email.attachment
    where: {trust: {max: external}}
  - name: run
    event: [file.exec, process.start]
    tainted_by: attach            # must descend from the attachment
    where: {fields.signed: false}
  - name: impact
    event: process.capability
    tainted_by: attach
    where: {fields.capabilities: [encrypt_bulk, delete_shadow_copies]}
  - name: c2
    event: net.flow
    tainted_by: attach
    where: {fields.beacon_score: {gte: 0.8}}
```

### An AI agent rule

```yaml
id: ai_indirect_injection_to_exfil
severity: critical
action: block
group_by: session_id
window: {steps: 20, seconds: 1800}
sequence:
  - name: inject
    event: [ai.retrieval, ai.tool_result]
    where:
      trust: {max: external}
    match:
      any:
        - regex: '(ignore|disregard|forget)\s+(all\s+|any\s+|your\s+)?(previous|prior|above|earlier)\s+instructions'
        - semantic: {cluster: prompt_injection, threshold: 0.55}
        - classifier: {label: injection, threshold: 0.8}
      escalate: Does this text try to give instructions to an AI assistant that differ from the user's task?
  - name: exfil
    event: ai.tool_call
    tainted_by: inject
    where:
      tool.name: [send_email, http_post, upload_file, post_message, create_gist]
      tool.dest_external: true
```

### Rule fields

| Field | Default | Meaning |
|---|---|---|
| `id` | required | Unique rule id |
| `title`, `description`, `tags` | — | Metadata (e.g. `atlas:AML.T0051`, `attack.t1059.001`) |
| `severity` | `medium` | `info` · `low` · `medium` · `high` · `critical` |
| `action` | `alert` | `allow` · `alert` · `redact` · `require_approval` · `block` |
| `response` | `[]` | SOAR hints passed to the caller, e.g. `isolate_host`, `open_case` |
| `confidence` | `0.8` | Base confidence, scaled by matcher scores |
| `group_by` | `session_id` | Field that keys sequence state: `host`, `user`, any dotted path |
| `window` | none | `{seconds: N}` and/or `{steps: N}` — how long a partial sequence lives |
| `sequence` | required | Ordered list of steps |
| `tests` | `[]` | Inline positive and negative test cases |

### Step fields

| Field | Meaning |
|---|---|
| `name` | Unique within the rule; other steps refer to it |
| `event` | Event type or list of types; globs allowed (`ai.*`, `process.*`) |
| `where` | Field predicates (see below) |
| `match` | Content matcher tree (`any` / `all`, nested, `min: N`, `escalate:`, `on: raw`) |
| `tainted_by` | Name of an earlier step this event must descend from |
| `min_attribution` | 0–1; require the tainted text to actually appear in this event, not just context taint |
| `same` | Fields that must equal the previous step's event, e.g. `[host, user]` |
| `count` | `{min: N, within: SECONDS, distinct: FIELD}` — the step completes after N matching events (or N distinct values of `distinct`) in a sliding window |
| `absent` | `true` makes this a "not followed by" step (see below) |
| `within` | Seconds a final `absent` step waits before firing |

### Counting and "not followed by"

```yaml
# 5 failed logins for a user within 5 minutes, then a success
group_by: user
sequence:
  - name: failures
    event: auth.login
    where: {fields.outcome: failure}
    count: {min: 5, within: 300}
  - name: success
    event: auth.login
    where: {fields.outcome: success}
```

```yaml
# one host touches 20 distinct ports in a minute
group_by: host
sequence:
  - name: scan
    event: net.flow
    count: {min: 20, within: 60, distinct: fields.dest_port}
```

```yaml
# a privileged login with no MFA for that user within 2 minutes
group_by: user
sequence:
  - name: login
    event: auth.login
    where: {fields.outcome: success, fields.privileged: true}
  - name: no_mfa
    event: auth.mfa
    absent: true
    within: 120
```

- **Absent in the middle** (`A`, not `B`, `C`): the partial match is dropped if `B` arrives before `C`.
- **Absent at the end** (`A`, not `B` within N seconds): only the clock can confirm it. `engine.advance_time(now)` returns these as separate verdicts marked `deferred`, never folded into the verdict of an unrelated event, so a time-out can't block an innocent tool call. `chain eval`, `chain replay`, inline tests and `evaluate_many` advance the clock for you.
- A count fires once per burst: the counter resets when it reaches `min`.
- An absent step can't be first, can't follow another absent step, and can't be the target of `tainted_by`. `same` works on it ("no MFA *for the same user*").

### `where` operators

```yaml
where:
  host: jump-01                       # equality
  tool.name: [send_email, http_post]  # any of
  fields.beacon_score: {gte: 0.8}     # gt, gte, lt, lte
  trust: {max: external}              # trust ≤ external (also min)
  fields.image: {regex: '\\psexec'}   # regex, contains, contains_all
  fields.user: {not_in: [svc_backup]} # eq, ne, in, not_in, exists
  rare: {field: fields.image_name, by: host, max_seen: 0}   # first time on this host
  sigma: {detection: {...}}           # embed a native Sigma detection block
```

Trust levels, least to most trusted: `untrusted` < `external` < `user` < `system`.

## Event schema

One schema covers classic telemetry and AI/agent telemetry.

```json
{
  "type": "ai.retrieval",
  "session_id": "s1",
  "host": "laptop-7",
  "user": "analyst@corp",
  "agent_id": "research-agent",
  "spans": [{"text": "...", "source": "web:vendor.example", "trust": "untrusted"}],
  "tool": {"name": "send_email", "args": {"to": "x@evil.io"}, "dest": "x@evil.io", "dest_external": true},
  "inputs": ["file:sha256:aa11"],
  "outputs": ["proc:4242"],
  "fields": {"command_line": "...", "signed": false}
}
```

- **Common types:** `email.attachment`, `file.create`, `file.exec`, `file.scan`, `process.start`, `process.capability`, `net.flow`, `net.dns`, `auth.login`, `auth.mfa`, `log.raw`, `ai.prompt`, `ai.retrieval`, `ai.tool_call`, `ai.tool_result`, `ai.memory_write`, `ai.output`. Any other string works too.
- **Spans** carry content with a source and a trust level. An event's trust is its least-trusted span.
- **`inputs` / `outputs`** are provenance edges. Taint flows from an untrusted event through every artifact it produces.
- **`fields`** holds free-form sensor output and Sigma-style log fields, accessed as `fields.<name>`.

## Using Chain inside an agent harness

```python
from chain import ChainGuard, Engine, ToolBlocked, ApprovalRequired
from chain.matchers import Judge

engine = Engine.from_paths("rules", "clusters", judge=Judge(my_llm_call))
guard = ChainGuard(engine, session_id=sid, agent_id="triage-agent", user="analyst@corp")

guard.on_prompt(user_text)                                         # trust: user
guard.on_retrieval(page_text, source="web:example.com")            # trust: untrusted
guard.on_tool_result("search", result_text)
guard.on_memory_write(note)
guard.on_output(answer)

guard.pre_tool_call("send_email", args, dest=to, external=True)    # raises ToolBlocked / ApprovalRequired
```

Or wrap tools directly:

```python
@guard.tool(external_dest=lambda a: a["to"], is_external=lambda d: not d.endswith("@corp.com"))
def send_email(to: str, body: str) -> str: ...
```

- `guard.tick(now=None)` advances the clock and returns deferred "not followed by" verdicts (also sent to `on_verdict`). They're never raised.
- `enforce=False` runs in monitor-only mode: verdicts are returned, never raised.
- `on_verdict=callback` receives every verdict that has hits, for logging or alerting.
- `Judge(fn)` takes any function from prompt string to model text. Content is wrapped as data, output must be JSON, and malformed output never counts as a hit.

## Importing Sigma and YARA

```bash
chain import-sigma examples/sigma_encoded_powershell.yml > rules/imported/enc_ps.yaml
chain import-yara  examples/sample.yar                    > rules/imported/ransom_note.yaml
```

- **Sigma** is evaluated natively: selections, keywords, field modifiers (`contains`, `startswith`, `endswith`, `re`, `all`, `base64`), `and` / `or` / `not`, `1 of selection_*`, `all of them`. You can also embed a Sigma `detection` block in any Chain step via `where: {sigma: ...}`.
- **YARA** text and regex strings convert to `strings` / `regex` matchers with `any`, `all` or `N of them`. Hex strings and modules are not converted yet — run native YARA as a sensor and feed its results in as `fields`.

## Testing and fuzzing rules

Every rule carries its own tests:

```yaml
tests:
  - name: injected vendor page leads to email
    expect: fire                 # fire | no_fire
    expect_action: block         # optional
    baseline: [...]              # optional events to seed baselines first
    events: [...]
    end_ts: 1700000600           # optional: advance the clock after the last event
```

`chain test` runs each case against a fresh engine. `chain fuzz` takes every `fire` case, mutates its content and reports recall per evasion technique:

```
classic_malicious_command_line
  zero_width           9/9     100% ####################
  homoglyph            9/9     100% ####################
  case                 9/9     100% ####################
  base64               9/9     100% ####################
  urlencode            9/9     100% ####################
  bury_in_document     9/9     100% ####################
  caret                9/9     100% ####################
```

`--min-recall 0.9` makes it a CI gate. Set `fuzz: false` on a case that shouldn't be mutated. An LLM paraphrase mutator can be plugged in through `extra_mutators`.

## Measuring rules on labeled data

`chain replay` runs labeled history through the engine and scores every rule. Add a `labels` list of rule ids to each event a rule *should* fire on:

```json
{"id": "e012", "type": "net.flow", "host": "ws-17", "inputs": ["proc:4242"], "fields": {"beacon_score": 0.91}, "labels": ["classic_phish_to_ransomware"]}
```

Label the event the rule fires on: the last step of a sequence, the event that crosses a count threshold, or, for a rule ending in "not followed by", the event the absence is measured from.

```
$ chain replay rules examples/labeled_events.jsonl --baseline examples/baseline_events.jsonl
rule                                         TP   FP   FN   prec recall
ai_indirect_injection_to_exfil                1    0    0   100%   100%
ai_intent_action_mismatch                     2    0    0   100%   100%
classic_brute_force_then_success              1    0    0   100%   100%
...
(all rules)                                  10    0    0   100%   100%
```

- `--baseline FILE` seeds `rare:` baselines with known-good history first.
- `--min-precision` / `--min-recall` fail the run if any rule falls below them. CI uses 0.9 for both.
- `--out report.json` writes the full report (including FP / FN event ids); CI uploads it on every run so you can track it over time.
- `-v` lists FP and FN event ids under each rule. Give events stable `id`s so these are meaningful.

The bundled `examples/labeled_events.jsonl` is a small synthetic set that guards against regressions. The real value comes from replaying your own labeled incidents and benign traffic.

## CLI reference

| Command | What it does |
|---|---|
| `chain validate RULES` | Compile rules and report errors |
| `chain test RULES` | Run inline rule tests |
| `chain fuzz RULES [--rounds N] [--min-recall R]` | Mutation-fuzz positive tests, exit non-zero below `R` |
| `chain eval RULES EVENTS.jsonl [--json]` | Run events through the engine and print verdicts |
| `chain replay RULES LABELED.jsonl [--baseline F] [--min-precision P] [--min-recall R] [--out F] [--json] [-v]` | Score rules against labeled events: TP / FP / FN, precision, recall |
| `chain import-sigma FILE` | Convert a Sigma rule to Chain YAML |
| `chain import-yara FILE` | Convert simple YARA rules to Chain YAML |

All rule commands accept `--clusters DIR` (default: `clusters/`).

## Project layout

```
chain/
  schema.py        Event, Span, ToolCall, Trust: one schema for classic + AI telemetry
  normalize.py     decoding and canonicalization before any match
  provenance.py    taint propagation over artifacts and agent context, attribution
  predicates.py    where-clause operators, rare: baselines
  matchers/        deterministic, semantic, classifier, LLM judge + cascade
  rules.py         rule model, validation, compiler
  engine.py        sequence state machine, event -> Verdict
  verdict.py       actions, evidence trail, explain()
  hooks.py         ChainGuard: harness hook points and enforcement
  importers/       Sigma (native evaluation + converter), YARA (basic)
  testing.py       inline tests, mutation fuzzer
  replay.py        labeled replay, precision / recall per rule
  cli.py           chain CLI
rules/ai/          injection-to-exfil, intent/action mismatch
rules/classic/     phish-to-ransomware, obfuscated commands, rare admin tools, brute force, port scan, login without MFA
clusters/          seed semantic clusters (prompt injection, malicious commands)
examples/          harness demo, sample + labeled events, Sigma and YARA rules to import
tests/             pytest suite
assets/            logo
```

### Bundled rules

| Rule | Action | Detects |
|---|---|---|
| `ai_indirect_injection_to_exfil` | block | Injected instructions in untrusted content, followed by an external send |
| `ai_intent_action_mismatch` | require_approval | A read-only request (summarize, explain …) followed by an external write |
| `classic_phish_to_ransomware` | alert | Attachment → unsigned exec → encryption / shadow deletion → beaconing |
| `classic_malicious_command_line` | alert | Download cradles, encoded PowerShell, shadow-copy deletion, obfuscated |
| `classic_rare_remote_admin_tool` | alert | A remote admin tool running for the first time on a host |
| `classic_brute_force_then_success` | alert | 5+ failed logins for a user in 5 minutes, then a success (counting) |
| `classic_port_scan` | alert | 20+ distinct destination ports from one host in a minute (distinct counting) |
| `classic_privileged_login_without_mfa` | alert | Privileged login with no MFA for that user within 2 minutes (absence) |

## Feature status

**Built** = working with tests · **Stub** = interface plus a simple default to swap out · **Planned** = designed, not built. Full list: [FEATURES.md](FEATURES.md).

| Area | Built | Stub / Planned |
|---|---|---|
| Event schema | One schema, trust per span, provenance edges, dotted fields | OCSF export |
| Normalization | NFKC, zero-width, homoglyphs, base64/hex/URL, PowerShell, caret | Full confusables table, concat unrolling, cross-document reassembly |
| Matchers | Regex, strings, N-of-M, semantic, judge, gray-zone escalation | Classifier is a keyword stub; FAISS; code/binary embeddings |
| Context | Artifact + context taint, attribution, baselines, `same:`, trust predicates | Asset/identity enrichment; Redis per-tenant baselines |
| Rule language | Sequences, windows, `group_by`, globs, actions, SOAR hints, counting, "not followed by" | — |
| Harness | Five hook points, `pre_tool_call` enforcement, decorator, monitor mode | Async alert-only evaluation, MCP proxy mode |
| Compatibility | Native Sigma, Sigma and YARA import | Sigma aggregations, YARA hex/modules, Suricata |
| Testing | Inline tests, baseline seeding, mutation fuzzer, labeled replay with precision/recall, CI gates | Dashboards over time |

## Roadmap

| Phase | Goal | Work |
|---|---|---|
| **1. Measure + language** ✅ | Prove that changes improve detection | `chain replay` with precision/recall per rule; "not followed by" steps; counting rules |
| **2. Production state** | Run as a multi-tenant service | Pluggable state store with a Redis backend; time-decayed baselines; asset/identity enrichment; async alert-only rules |
| **3. Evasion resistance** | Close the remaining disguise tricks | Full Unicode confusables; string-concat and variable unrolling; cross-document chunk reassembly; matching fuzz mutators |
| **4. Real models** | Replace stubs, checked against Phase 1 replay | Trained per-label classifiers; vector index; built-in Claude judge; code/binary embeddings |
| **5. Integrations** | Plug into existing tools and agents | MCP proxy mode; OCSF export; Sigma aggregations; YARA hex/modules; Suricata import |

Phases 1, 3 and 5 can run in parallel; Phase 4 depends on Phase 1. MCP proxy mode can move earlier for AI-agent security pilots.

## Production swaps

| Scaffold default | Replace with |
|---|---|
| Hashed n-gram embedder | `CHAIN_EMBEDDER=sentence-transformers:intfloat/multilingual-e5-small` |
| In-memory cluster index | FAISS or a vector DB |
| Keyword classifier | Fine-tuned small models per label |
| In-memory state and baselines | Redis, per tenant, time-decayed |
| No judge | Your LLM call via `Judge(fn)`; never give it tools or final approval on high-risk actions |
| Python hot path | Rust for normalizer, regex (Hyperscan) and state store when latency matters |

## Design notes

- **Taint inside an LLM is approximate.** Chain taints the whole agent context conservatively once untrusted content enters it, then reports an attribution score so rules can demand copy-through evidence with `min_attribution`.
- **The judge is a target.** Content is wrapped as data, output must be JSON, malformed output never counts as a hit, and the judge is never the sole approver.
- **Cheap first.** Most events are decided by event type and field checks; expensive tiers run only on what survives.
- **Evidence over scores.** Every verdict carries the events, fields, matchers, tiers and taint path that produced it.

## License

[MIT](LICENSE) © 2026 Darshik Gori
