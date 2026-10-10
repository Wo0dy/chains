# Chain

A detection language for classic and agentic SecOps. It does what YARA, Sigma and Suricata rules do, then adds what they can't: matching on **meaning**, tracking **provenance and taint** across events, **multi-step sequences**, per-entity **baselines**, and **inline enforcement** inside an agent harness.

Full feature list with build status: [FEATURES.md](FEATURES.md)

## Quick start

```bash
pip install -e ".[dev]"
chain validate rules
chain test rules                 # inline rule tests
chain fuzz rules --min-recall 0.9  # adversarial mutations, recall per technique
chain eval rules examples/events.jsonl
python examples/agent_harness_demo.py
pytest -q
```

## Layout

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
  cli.py           chain CLI
rules/ai/          injection-to-exfil, intent/action mismatch
rules/classic/     phish-to-ransomware chain, obfuscated commands, rare admin tools
clusters/          seed semantic clusters (prompt injection, malicious commands)
examples/          harness demo, sample events, Sigma and YARA rules to import
tests/             pytest suite
```

## A rule

```yaml
id: classic_phish_to_ransomware
severity: critical
action: alert
response: [isolate_host, kill_process_tree, open_case]
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
tests:
  - name: full chain
    expect: fire
    events: [...]
```

Content matching uses tiers, cheapest first:

```yaml
match:
  any:
    - regex: 'downloadstring|net\.webclient'
    - semantic: {cluster: malicious_commands, threshold: 0.62}
    - classifier: {label: destructive, threshold: 0.85}
  escalate: Is this command malicious?   # LLM judge only in the gray zone
```

## In a harness

```python
from chain import ChainGuard, Engine, ToolBlocked

engine = Engine.from_paths("rules", "clusters", judge=Judge(my_llm_call))
guard = ChainGuard(engine, session_id=sid, agent_id="triage-agent")

guard.on_prompt(user_text)
guard.on_retrieval(page_text, source="web:example.com", trust="untrusted")
guard.pre_tool_call("send_email", args, dest=to, external=True)  # raises ToolBlocked
```

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
- **Evidence over scores.** Every verdict carries the events, fields, matchers, tiers and taint path that produced it.
