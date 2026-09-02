# Design Document

## Overview

Phase 5 layers professional deliverables and collaboration features onto the existing reporter, evidence, and persistence modules. It reuses the current APIs (`generate_executive_summary`, `generate_technical_report`, `export_markdown`, `export_json`, `EvidenceCollector`, `save_state`/`load_state`) and extends them rather than replacing them.

### Design Principles

- **Single layout source.** HTML is rendered from Jinja2 templates; PDF is produced from that HTML via WeasyPrint, so there is one layout to maintain.
- **Escape everything.** All dynamic content (tool output can contain HTML/script) is auto-escaped by the template engine.
- **Reuse Phase 4 safety.** Evidence paths, report paths, and archive members are validated with the Path_Validator; notifications and exports redact via the Secrets_Manager.
- **Optional heavy deps are lazy.** WeasyPrint and webhook HTTP are imported only when used, so the core stays lightweight.

## Architecture

```
                 ┌──────────────────────────────────────┐
                 │            reporter.py                 │
                 │  generate_* (existing)                 │
                 │  render_html() ──uses──> templates/    │
                 │  export_html()  export_pdf()  export_json│
                 └───────────┬───────────────┬────────────┘
                             │ Jinja2         │ WeasyPrint (lazy)
                             ▼                ▼
                 quarr/templates/         report.pdf
                   executive.html.j2
                   technical.html.j2
                   base.html.j2

  evidence.py (extended)          timeline.py            dedup.py
   + sha256 per item               aggregate events       merge duplicates
   + index w/ hashes               from state             idempotent
   + verify_chain()                → json / text          dry-run

  persistence.py (extended)        integrations/notifications.py
   + export_bundle() .zip           Slack/Discord webhooks
   + import_bundle() (zip-slip safe) redacted, non-fatal
```

### Report Rendering Flow

```
export_pdf(state, path, type)
  └─> html = render_html(state, type)          # Jinja2, autoescape
        └─> export_html writes html
  └─> weasyprint.HTML(string=html).write_pdf(path)   # lazy import
```

## Components and Interfaces

### `quarr/core/reporter.py` (extended)

```python
def render_html(state, report_type="technical", template_path=None) -> str:
    env = Environment(loader=..., autoescape=select_autoescape(["html"]))
    tmpl = env.get_template(template_path or f"{report_type}.html.j2")
    ctx = _build_context(state)     # eng meta, findings, severity counts, ts
    return tmpl.render(**ctx)

def export_html(state, filepath, report_type="technical", template_path=None) -> str: ...
def export_pdf(state, filepath, report_type="technical") -> str:
    try:
        import weasyprint
    except ImportError:
        raise QuarrError("WeasyPrint not installed. pip install weasyprint")
    html = render_html(state, report_type)
    weasyprint.HTML(string=html).write_pdf(filepath)

def export_json(state, filepath) -> str:      # enhanced: schema_version, evidence-by-ref
```

`_build_context` reuses existing `_count_by_severity`, `_risk_rating`, and CWE/CVSS enrichment from `knowledge.base`.

### `quarr/templates/`

- `base.html.j2` — layout + inline CSS (severity colors), blocks for title/body.
- `executive.html.j2`, `technical.html.j2` — extend base; iterate findings, evidence, remediation.
- Jinja2 `autoescape` on for `.html`/`.j2` (Req 1.4, 4.5).

### `quarr/core/evidence.py` (extended)

Adds hashing + chain of custody to the existing `Evidence`/`EvidenceCollector`:

```python
@dataclass
class Evidence:
    ...                      # existing fields
    sha256: str = ""
    collector: str = "quarr"
    custody: list[dict] = field(default_factory=list)  # append-only events

class EvidenceCollector:
    def collect(...):        # existing; now computes sha256 over stored content
        ...
        ev.sha256 = hashlib.sha256(content.encode()).hexdigest()
        ev.custody.append({"event":"acquired","ts":ev.timestamp})
    def verify_chain(self) -> list[dict]:   # recompute file hash vs recorded
        # returns [{id, ok, expected, actual}] flagging tampered
    def save_index(self):    # existing; now includes sha256 + custody
```

Evidence file paths validated via Phase 4 `path.validate_within(path, evidence_dir)` (Req 5.5).

### `quarr/core/timeline.py`

```python
@dataclass
class TimelineEvent:
    ts: datetime; kind: str; asset: str | None; detail: str; ref_id: str | None

def build_timeline(state, evidence=None) -> list[TimelineEvent]:
    # from state.tool_history (ts), findings (status/created), evidence (ts)
def to_json(events) -> str: ...
def to_text(events) -> str: ...
def filter_events(events, *, since=None, until=None, kind=None, asset=None): ...
```

Reconstructable from persisted `PentestState` alone (Req 7.6).

### `quarr/core/persistence.py` (extended)

```python
def export_bundle(engagement_id, out_path) -> str:
    # zip state.json + evidence/ + index.json; redact state summary secrets
def import_bundle(bundle_path, dest_base=ENGAGEMENTS_DIR) -> PentestState:
    with zipfile.ZipFile(bundle_path) as z:
        for m in z.namelist():
            _reject_zip_slip(m, dest_base)     # commonpath check
        z.extractall(dest_base)
    state = load_state(engagement_id)
    # verify evidence hashes → warn on mismatch
    return state
```

Zip-slip protection resolves each member against the destination and rejects escapes (Req 8.6), reusing the Phase 4 path logic.

### `quarr/core/dedup.py`

```python
def _key(f: Finding) -> tuple:
    return (normalize(f.title), f.asset, cwe_of(f))
def deduplicate(state, *, dry_run=False) -> DedupReport:
    # group by _key; merge evidence/observation_ids; keep max severity/confidence
    # idempotent; dry_run returns proposed merges without mutating
```

### `quarr/integrations/notifications.py`

```python
class Notifier:
    def __init__(self, slack_url=None, discord_url=None,
                 threshold=Severity.HIGH, enabled=False): ...
    def notify_finding(self, finding: Finding) -> None:
        if not self.enabled: return
        if finding.severity below threshold or status != CONFIRMED: return
        payload = redact(_format(finding))          # Phase 4 Secrets_Manager
        try: httpx.post(url, json=payload, timeout=10)
        except Exception as e: log.warning("notify_failed", error=str(e))  # non-fatal
```

Disabled by default; only active when a webhook URL is configured (Req 10.7).

## Data Models

- `Evidence` extended with `sha256`, `collector`, `custody` (append-only list). Backward compatible (defaults).
- New dataclasses: `TimelineEvent`, `DedupReport`.
- `export_json` schema gains `schema_version` and evidence-by-reference.
- `Settings` extended: `slack_webhook_url`, `discord_webhook_url`, `notify_enabled`, `notify_threshold`.
- No breaking changes to `PentestState`/`Finding`.

## Error Handling

- Missing WeasyPrint → clear `QuarrError` with install hint; agent does not crash (Req 2.3).
- Evidence hash mismatch → flagged in `verify_chain` / import warnings, not an exception during normal flow.
- Zip-slip attempt on import → `ValidationError` before extraction of the offending member.
- Notification failure → WARNING log, swallowed (Req 10.5).
- Template not found / custom path invalid → `QuarrError` with the attempted path.

## Testing Strategy

Offline, fixture-based, using `tmp_path` for all file output.

- **reporter**: `render_html` from `populated_state` contains findings and escapes a `<script>` payload injected via a finding title; `export_html` writes a file; `export_pdf` raises clear error when WeasyPrint absent (monkeypatch import) and writes non-empty PDF when present (skip if not installed); `export_json` round-trips and includes `schema_version`.
- **templates**: custom template path is used; autoescape verified.
- **evidence**: `collect` sets sha256; `verify_chain` passes for untampered and flags a manually altered file; index includes hash/custody; path traversal rejected.
- **timeline**: events aggregated and ordered; JSON/text export; filter by range/kind/asset; rebuild from loaded state.
- **persistence bundle**: export then import round-trips a populated engagement; zip-slip member rejected; evidence hashes verified on import; secrets redacted in bundled summary.
- **dedup**: duplicates merged with max severity/confidence and combined evidence; idempotent; dry-run reports without mutating.
- **notifications**: disabled by default; enabled + HIGH/CONFIRMED triggers a mocked `httpx.post`; secrets redacted; delivery failure logged and non-fatal.

## Dependencies Added

```
jinja2>=3.1.0
weasyprint>=60.0     # optional; lazy-imported for PDF only
```

`httpx` (already present) is reused for webhooks. `hashlib`, `zipfile`, `shutil` are stdlib.
