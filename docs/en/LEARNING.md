# Cross-Engagement Learning

QUARR accumulates knowledge from the engagements it runs and reuses it on future
ones, so the agent becomes more targeted over time. This is distinct from the
static RAG catalog (`quarr/knowledge/base.py`, OWASP/CWE/MITRE) — the learning
layer (`quarr/knowledge/learned.py`) is **persistent and grows from your own
assessments**.

## What it learns

1. **Finding patterns** — for each technology (e.g. `Werkzeug`, `Apache`), which
   vulnerability types were previously CONFIRMED and by which tool.
2. **Tool effectiveness** — success/attempt counts per `(technology, tool)`, used
   to suggest the highest-yield tool for a given stack.

Only CONFIRMED findings are recorded. The store contains **no secrets** — just
technology labels, coarse vuln-type labels, tool names, and short finding titles.

## How it works

- **Recording (automatic):** when an engagement run concludes, the agent calls
  `record_from_state()`, persisting confirmed findings + tool outcomes.
- **Retrieval (automatic):** at the start of the next engagement, relevant learned
  hints (matched by the target's discovered technologies) are injected into the
  LLM context under a `LEARNED KNOWLEDGE (from previous engagements)` block.

Example hint injected into a later Werkzeug/Flask target:

```
LEARNED KNOWLEDGE (from previous engagements):
  • On Werkzeug: previously confirmed excessive-data-exposure (via api_data_exposure_check) — seen 3x.
    ↳ Most effective tool on Werkzeug: api_data_exposure_check (100% success over 4)
  • On Werkzeug: previously confirmed bola (via api_bola_check) — seen 2x.
Prioritize these checks/tools where applicable.
```

## Storage

- Location: `$QUARR_LEARN_DIR/learned_knowledge.json` (default `~/.quarr/`).
- Written atomically (temp file + replace), deduplicated on
  `(technology, vuln_type, tool)`, and bounded to the 500 most-recent patterns.
- A corrupt store never crashes an engagement — it degrades to empty and rebuilds.

## Inspecting & resetting

- In the CLI, type `learnings` to print a summary of what QUARR has learned.
- Programmatically:

```python
from quarr.knowledge import learned
print(learned.summary())          # human-readable overview
learned.get_hints(["Werkzeug"])   # hints for a technology
learned.reset_store()             # wipe learned knowledge
```

- To isolate learning (e.g. per client or in tests), set `QUARR_LEARN_DIR` to a
  dedicated directory.

## Limitations

- Finding→tool attribution is best-effort: a finding is associated with the
  engagement's tool activity, not a strict per-finding tool link (the state model
  does not record which tool produced which finding). Tool-effectiveness stats
  are precise; the "via <tool>" label on a pattern is indicative.
- Learning improves targeting/prioritization; it does not change tool behavior or
  bypass the policy engine and scope controls.
