# Requirements Document

## Introduction

This document specifies the requirements for **Phase 5: Enhanced Features** of the QUARR Agent. With a hardened, tested core in place (Phases 1-4), Phase 5 adds professional deliverables and workflow features: HTML/PDF/JSON report export with customizable templates, robust evidence management with cryptographic hashing and chain of custody, timeline reconstruction, session export/import for collaboration, finding deduplication, and optional Slack/Discord notifications.

This phase builds on existing modules: `quarr/core/reporter.py` (already has `generate_executive_summary`, `generate_technical_report`, `export_markdown`, `export_json`), `quarr/core/evidence.py` (`EvidenceCollector`), and `quarr/core/persistence.py` (`save_state`/`load_state`/`list_engagements`).

## Glossary

- **Report_Generator**: The reporting subsystem (`quarr/core/reporter.py`) producing assessment reports
- **Report_Template**: A customizable template driving report layout and styling
- **Evidence_Manager**: The evidence subsystem (`quarr/core/evidence.py`) storing and hashing artifacts
- **Chain_Of_Custody**: The tamper-evident record proving evidence integrity over time
- **Timeline**: A chronological reconstruction of assessment/incident events
- **Session_Bundle**: A portable, self-contained export of an engagement for sharing
- **Deduplicator**: The component that merges duplicate findings
- **Notifier**: The component that sends alerts to Slack/Discord

## Requirements

### Requirement 1: HTML Report Export

**User Story:** As a consultant, I want professional HTML reports, so that I can deliver readable, styled findings to clients.

#### Acceptance Criteria

1. THE Report_Generator SHALL provide `export_html(state, filepath, report_type)` in `quarr/core/reporter.py`
2. THE HTML report SHALL include: title page, executive summary, severity breakdown, per-finding sections with evidence, and remediation
3. THE HTML report SHALL be self-contained (inline CSS) so it renders without external assets
4. THE HTML report SHALL escape all dynamic content to prevent HTML/script injection from tool output
5. THE HTML report SHALL render severity with consistent color coding
6. WHEN the state has no findings, THE HTML report SHALL render a valid "no findings" report

### Requirement 2: PDF Report Export

**User Story:** As a consultant, I want PDF export, so that I can deliver a portable, print-ready report.

#### Acceptance Criteria

1. THE Report_Generator SHALL provide `export_pdf(state, filepath, report_type)` using WeasyPrint
2. THE PDF export SHALL render the same content as the HTML report
3. WHEN WeasyPrint is not installed, THE export SHALL raise a clear error instructing installation, without crashing the agent
4. THE PDF export SHALL be generated from the HTML representation to keep a single layout source
5. THE PDF export SHALL succeed for a populated state and produce a non-empty PDF file

### Requirement 3: JSON Export Enhancement

**User Story:** As an integrator, I want a well-structured JSON export, so that findings can be consumed by other tools.

#### Acceptance Criteria

1. THE Report_Generator SHALL provide/enhance `export_json(state, filepath)` producing a documented schema
2. THE JSON export SHALL include: engagement metadata, hosts, services, findings (with severity, status, confidence, CWE, CVSS, evidence references), and tool history
3. THE JSON export SHALL be valid JSON that round-trips (parseable back into structures)
4. THE JSON schema SHALL be versioned with a `schema_version` field
5. THE JSON export SHALL reference evidence by ID and hash rather than embedding large raw content

### Requirement 4: Report Templates

**User Story:** As a team, I want customizable report templates, so that reports match our branding and structure.

#### Acceptance Criteria

1. THE system SHALL store templates under `quarr/templates/`
2. THE Report_Generator SHALL render reports using a template engine (Jinja2) with a default template provided
3. THE templates SHALL support variables for engagement metadata, findings, severity counts, and generation timestamp
4. WHEN a custom template path is provided, THE Report_Generator SHALL use it instead of the default
5. THE template rendering SHALL auto-escape content by default to prevent injection
6. THE default template SHALL cover executive and technical report types

### Requirement 5: Evidence Storage

**User Story:** As an analyst, I want structured evidence storage, so that all artifacts are organized per engagement and finding.

#### Acceptance Criteria

1. THE Evidence_Manager SHALL store evidence under `engagements/<id>/evidence/` (consistent with existing `EvidenceCollector`)
2. THE Evidence_Manager SHALL support evidence types: tool_output, screenshot, request_response, file, and note
3. THE Evidence_Manager SHALL persist an evidence index (`index.json`) mapping IDs to metadata and file paths
4. THE Evidence_Manager SHALL associate each evidence item with a finding ID
5. THE Evidence_Manager SHALL validate evidence file paths via the Phase 4 Path_Validator to prevent traversal
6. THE Evidence_Manager SHALL store large content in files and reference by path rather than inflating state

### Requirement 6: Evidence Hashing and Chain of Custody

**User Story:** As a forensic examiner, I want cryptographic hashing of evidence, so that integrity can be proven for legal defensibility.

#### Acceptance Criteria

1. THE Evidence_Manager SHALL compute a SHA-256 hash of each evidence item's content at collection time
2. THE Evidence_Manager SHALL record the hash, collector, and timestamp in the evidence index
3. THE Chain_Of_Custody SHALL provide a verification function that recomputes hashes and reports any mismatch
4. WHEN an evidence file's recomputed hash does not match the recorded hash, THE verification SHALL flag it as tampered
5. THE Chain_Of_Custody record SHALL be append-only and include acquisition time and any access events
6. THE hashing SHALL cover the stored file content, and the index entry SHALL be independently verifiable

### Requirement 7: Timeline Reconstruction

**User Story:** As a DFIR analyst, I want a timeline of events, so that I can reconstruct the sequence of activity during an assessment or incident.

#### Acceptance Criteria

1. THE Timeline SHALL be implemented in `quarr/core/timeline.py`
2. THE Timeline SHALL aggregate events from: tool executions, findings status transitions, and evidence collection
3. THE Timeline SHALL order events chronologically by timestamp
4. THE Timeline SHALL support export to JSON and a human-readable text format
5. THE Timeline SHALL support optional filtering by time range, event type, and asset
6. THE Timeline SHALL be reconstructable from a persisted state without requiring live objects

### Requirement 8: Session Export/Import

**User Story:** As a collaborator, I want to export and import engagement sessions, so that I can share work with teammates.

#### Acceptance Criteria

1. THE system SHALL provide session export/import in `quarr/core/persistence.py`
2. THE Session_Bundle SHALL be a single archive (e.g., `.zip`) containing state, evidence files, and evidence index
3. WHEN a Session_Bundle is imported, THE system SHALL reconstruct the engagement directory and load the state
4. THE import SHALL verify evidence hashes on load and warn on mismatches
5. THE export SHALL redact secrets from state summaries per the Phase 4 Secrets_Manager before bundling
6. THE import SHALL validate archive member paths to prevent zip-slip path traversal
7. THE export/import SHALL round-trip a populated engagement without data loss

### Requirement 9: Finding Deduplication

**User Story:** As an analyst, I want duplicate findings merged, so that reports are not cluttered with repeated issues.

#### Acceptance Criteria

1. THE Deduplicator SHALL be implemented in `quarr/core/dedup.py`
2. THE Deduplicator SHALL identify duplicates by matching normalized title, asset, and finding type/CWE
3. WHEN duplicates are found, THE Deduplicator SHALL merge them, combining evidence and keeping the highest severity and confidence
4. THE Deduplicator SHALL preserve all merged evidence references and observation IDs
5. THE Deduplicator SHALL be idempotent (running twice yields the same result)
6. THE Deduplicator SHALL provide a dry-run mode reporting proposed merges without applying them

### Requirement 10: Notifications

**User Story:** As a team lead, I want Slack/Discord notifications, so that I am alerted when significant findings occur.

#### Acceptance Criteria

1. THE Notifier SHALL be implemented in `quarr/integrations/notifications.py`
2. THE Notifier SHALL support Slack and Discord webhook delivery
3. THE Notifier SHALL send an alert when a finding reaches CONFIRMED status at HIGH or CRITICAL severity
4. THE Notifier SHALL redact secrets and sensitive evidence from notification content
5. WHEN a webhook delivery fails, THE Notifier SHALL log the failure and SHALL NOT crash the agent
6. THE Notifier SHALL be configurable via settings (webhook URLs, enabled/disabled, severity threshold)
7. THE Notifier SHALL be disabled by default and only active when a webhook URL is configured
