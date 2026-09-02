# Implementation Plan

Execute top to bottom. Builds on existing reporter/evidence/persistence and Phase 4 validators/secrets. Each task ends with a runnable verification.

- [x] 1. Add reporting dependencies and templates scaffold
  - Add `jinja2>=3.1.0` and `weasyprint>=60.0` (mark WeasyPrint optional in comments) to `requirements.txt`; install jinja2 (`venv/bin/pip install jinja2`)
  - Create `quarr/templates/` with `base.html.j2` (inline CSS, severity colors), `executive.html.j2`, `technical.html.j2` extending base
  - _Verify:_ `venv/bin/python -c "import jinja2; from jinja2 import Environment, FileSystemLoader; Environment(loader=FileSystemLoader('quarr/templates')).get_template('technical.html.j2')"` succeeds
  - _Requirements: 4.1, 4.2, 4.3, 4.6_

- [x] 2. Implement HTML report export
  - Add `render_html(state, report_type, template_path)` and `export_html(...)` to `quarr/core/reporter.py` using Jinja2 with `autoescape`; build context from existing severity/CWE/CVSS helpers
  - Support custom template path; handle empty-findings state
  - _Verify:_ `tests/test_report_html.py` — HTML contains findings; a `<script>` in a finding title is escaped; empty state renders valid HTML; custom template used. Run `venv/bin/pytest tests/test_report_html.py -v`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 4.4, 4.5_

- [x] 3. Implement PDF export
  - Add `export_pdf(state, filepath, report_type)` rendering from `render_html`, lazily importing WeasyPrint; raise clear `QuarrError` with install hint if missing
  - _Verify:_ `tests/test_report_pdf.py` — monkeypatch missing import → clear error; if WeasyPrint installed, produces non-empty PDF (else `pytest.skip`). Run `venv/bin/pytest tests/test_report_pdf.py -v`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 4. Enhance JSON export
  - Enhance `export_json` to include `schema_version`, engagement metadata, hosts/services, findings (severity/status/confidence/CWE/CVSS/evidence refs), tool history; reference evidence by ID+hash
  - _Verify:_ `tests/test_report_json.py` — output parses back; contains `schema_version`; evidence referenced by id/hash not embedded. Run `venv/bin/pytest tests/test_report_json.py -v`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 5. Evidence hashing and chain of custody
  - Extend `quarr/core/evidence.py`: add `sha256`, `collector`, `custody` to `Evidence`; compute SHA-256 on collect; add `verify_chain()`; include hash/custody in `save_index`; validate paths via Phase 4 `path.validate_within`
  - _Verify:_ `tests/test_evidence.py` — collect sets sha256; verify_chain OK untampered and flags an altered file; index has hash/custody; traversal path rejected. Run `venv/bin/pytest tests/test_evidence.py -v`
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

- [x] 6. Timeline reconstruction
  - Create `quarr/core/timeline.py` with `TimelineEvent`, `build_timeline(state, evidence)`, `to_json`, `to_text`, `filter_events`
  - Aggregate tool executions, finding transitions, evidence; order chronologically; rebuildable from persisted state
  - _Verify:_ `tests/test_timeline.py` — events ordered; JSON/text export; filter by range/kind/asset; rebuild from loaded state. Run `venv/bin/pytest tests/test_timeline.py -v`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [x] 7. Session export/import bundle
  - Extend `quarr/core/persistence.py` with `export_bundle(engagement_id, out_path)` (zip state+evidence+index, redact summary secrets) and `import_bundle(bundle_path)` with zip-slip protection and evidence-hash verification
  - _Verify:_ `tests/test_bundle.py` (tmp_path) — export→import round-trips populated engagement; zip-slip member rejected; hash mismatch warned; secrets redacted. Run `venv/bin/pytest tests/test_bundle.py -v`
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

- [x] 8. Finding deduplication
  - Create `quarr/core/dedup.py` with `deduplicate(state, dry_run)` matching normalized title+asset+CWE; merge evidence/observation_ids, keep max severity/confidence; idempotent; dry-run report
  - _Verify:_ `tests/test_dedup.py` — duplicates merged correctly; idempotent second run; dry-run does not mutate. Run `venv/bin/pytest tests/test_dedup.py -v`
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

- [x] 9. Notifications
  - Create `quarr/integrations/__init__.py` and `notifications.py` with `Notifier` (Slack/Discord webhooks via httpx); send on CONFIRMED HIGH/CRITICAL; redact via Phase 4 secrets; non-fatal on failure; disabled by default; settings-driven
  - Add notify settings to `Settings` and `.env.example`
  - _Verify:_ `tests/test_notifications.py` — disabled by default; enabled+HIGH/CONFIRMED calls mocked `httpx.post`; secrets redacted; delivery failure logged not raised. Run `venv/bin/pytest tests/test_notifications.py -v`
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

- [x] 10. Phase 5 verification pass
  - Run full suite `venv/bin/pytest tests/ -v`
  - Import smoke: `venv/bin/python -c "import quarr.core.timeline, quarr.core.dedup, quarr.integrations.notifications; from quarr.core.reporter import export_html, export_pdf"`
  - Update `TASKS.md` Phase 5 rows to ✅ and progress table
  - _Verify:_ full pytest green; imports succeed; TASKS.md updated
  - _Requirements: all Phase 5 requirements_
