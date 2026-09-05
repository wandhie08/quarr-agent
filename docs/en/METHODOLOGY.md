# Methodology Knowledge (Reference Playbooks)

QUARR ships phase-appropriate **methodology playbooks** that are injected into
the agent's LLM context (RAG) so it recalls a proven approach at the relevant
pentest phase — e.g. an Active Directory attack chain during the exploit phase,
or the OWASP API Top 10 checklist against an API target.

## What it is (and isn't)

Each playbook is a compact, factual mapping:

```
phase → techniques → tools → short checklist  (+ source attribution)
```

These encode **facts and structure** distilled from well-known references — which
tools/techniques apply to which phase — **not** the copyrighted prose of those
books. Every playbook cites its source(s).

## Sources

| Source | License / note | Contributes |
|--------|----------------|-------------|
| OWASP MASTG | Creative Commons (CC BY-SA) | Mobile MASVS playbook (STORAGE/CRYPTO/NETWORK/PLATFORM/AUTH/RESILIENCE) |
| The Hacker Playbook 3 (P. Kim) | facts/structure only | Recon, web exploitation, network/AD, privesc, persistence, social eng |
| Operator Handbook (J. Picolet) | facts/structure only | Red-team, OSINT, AD, privesc |
| Hacking APIs (C. J. Ball) | facts/structure only | API Security (BOLA, JWT, mass assignment, GraphQL) |
| Bug Bounty Bootcamp (V. Li) | facts/structure only | Web bug-hunting (XSS/CSRF/SSRF/XXE/IDOR) |
| The Web Application Hacker's Handbook (Stuttard & Pinto) | facts/structure only | Web auth / access-control methodology |
| RTFM v2 (B. Clark) | facts/structure only | Operator command-reference loop |

> Only OWASP MASTG is redistributable content (CC-licensed). For the commercial
> books, QUARR stores **no verbatim text** — only factual phase→technique→tool
> mappings and short original checklists. If you own these books, they remain
> the best full reference.

## How it works

- The agent computes the current phase (`recon`/`discovery`/`vuln_scan`/`exploit`)
  and the target's discovered technologies/services.
- `quarr/knowledge/methodology.get_methodology(phase, domains, query)` returns the
  1–2 most relevant playbooks, formatted with a `Source:` line, which are appended
  to the LLM context alongside the static RAG knowledge and cross-engagement
  learned hints.

## Inspecting

```python
from quarr.knowledge.methodology import list_playbooks, get_methodology
list_playbooks()
print(get_methodology(phase="vuln_scan", domains=["api"], query="test for bola"))
```
