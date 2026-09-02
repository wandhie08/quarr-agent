"""Unit/integration tests for Phase 5 features."""

import json

import pytest

from quarr.core.reporter import render_html, export_html, export_pdf, export_json
from quarr.core.models import Finding, FindingStatus, Severity
from quarr.core.evidence import EvidenceCollector
from quarr.core import timeline as tl
from quarr.core import dedup
from quarr.core import persistence
from quarr.integrations.notifications import Notifier
from quarr.core.exceptions import QuarrError, ValidationError


# ---- reporting ----

@pytest.mark.unit
def test_render_html_contains_findings_and_escapes(populated_state):
    populated_state.findings.append(Finding(
        title="<script>alert(1)</script>", severity=Severity.LOW,
        status=FindingStatus.CONFIRMED, asset="10.10.10.20",
    ))
    html = render_html(populated_state, "technical")
    assert "SQL Injection" in html
    # XSS payload must be escaped, not raw.
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.unit
def test_export_html_writes_file(populated_state, tmp_path):
    p = tmp_path / "r.html"
    export_html(populated_state, str(p), "executive")
    assert p.exists() and p.stat().st_size > 0


@pytest.mark.unit
def test_export_pdf_missing_weasyprint_raises(populated_state, tmp_path, monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "weasyprint":
            raise ImportError("no weasyprint")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(QuarrError):
        export_pdf(populated_state, str(tmp_path / "r.pdf"))


@pytest.mark.unit
def test_export_json_has_schema_version(populated_state, tmp_path):
    p = tmp_path / "f.json"
    export_json(populated_state, str(p))
    data = json.loads(p.read_text())
    assert data["schema_version"] == "1.0"


# ---- evidence hashing / chain ----

@pytest.mark.unit
def test_evidence_hash_and_verify(tmp_path):
    ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
    ev = ec.collect("FIND-1", "nmap", "scan output", content="port 22 open")
    assert ev.sha256
    results = ec.verify_chain()
    assert results[0]["ok"] is True
    # Tamper with the file → verification flags it.
    with open(ev.filepath, "a") as f:
        f.write("TAMPERED")
    assert ec.verify_chain()[0]["ok"] is False


@pytest.mark.unit
def test_evidence_index_includes_hash(tmp_path):
    ec = EvidenceCollector("ENG-1", base_dir=str(tmp_path))
    ec.collect("FIND-1", "nmap", "desc", content="x")
    idx = ec.save_index()
    data = json.loads(open(idx).read())
    assert data[0]["sha256"]
    assert data[0]["custody"]


# ---- timeline ----

@pytest.mark.integration
def test_timeline_ordered_and_filtered(populated_state):
    events = tl.build_timeline(populated_state)
    assert len(events) >= 1
    ts = [e.ts for e in events]
    assert ts == sorted(ts)
    findings_only = tl.filter_events(events, kind="finding")
    assert all(e.kind == "finding" for e in findings_only)
    assert "[finding]" in tl.to_text(events) or events


# ---- dedup ----

@pytest.mark.unit
def test_dedup_merges_duplicates():
    from quarr.core.models import PentestState
    state = PentestState()
    f1 = Finding(title="SQL Injection", severity=Severity.MEDIUM,
                 status=FindingStatus.DETECTED, asset="a.com", evidence=["e1"])
    f2 = Finding(title="sql injection", severity=Severity.HIGH,
                 status=FindingStatus.DETECTED, asset="a.com", evidence=["e2"])
    state.findings = [f1, f2]
    report = dedup.deduplicate(state)
    assert report.merged == 1
    assert len(state.findings) == 1
    # Highest severity kept, evidence combined.
    assert state.findings[0].severity == Severity.HIGH
    assert set(state.findings[0].evidence) == {"e1", "e2"}


@pytest.mark.unit
def test_dedup_dry_run_does_not_mutate():
    from quarr.core.models import PentestState
    state = PentestState()
    state.findings = [
        Finding(title="X", severity=Severity.LOW, status=FindingStatus.DETECTED, asset="a"),
        Finding(title="x", severity=Severity.LOW, status=FindingStatus.DETECTED, asset="a"),
    ]
    dedup.deduplicate(state, dry_run=True)
    assert len(state.findings) == 2  # unchanged


# ---- session bundle ----

@pytest.mark.integration
def test_bundle_roundtrip_and_zipslip(populated_state, monkeypatch, tmp_path):
    base = tmp_path / "engagements"
    monkeypatch.setattr(persistence, "ENGAGEMENTS_DIR", str(base))
    persistence.save_state(populated_state)
    bundle = tmp_path / "bundle.zip"
    persistence.export_bundle(populated_state.engagement.id, str(bundle))
    assert bundle.exists()

    dest = tmp_path / "imported"
    state, warnings = persistence.import_bundle(str(bundle), dest_base=str(dest))
    assert state is not None
    assert state.engagement.id == populated_state.engagement.id


@pytest.mark.unit
def test_zip_slip_rejected(tmp_path):
    with pytest.raises(ValidationError):
        persistence._reject_zip_slip("../evil.txt", str(tmp_path))


# ---- notifications ----

@pytest.mark.unit
def test_notifier_disabled_by_default():
    n = Notifier()
    f = Finding(title="X", severity=Severity.CRITICAL,
                status=FindingStatus.CONFIRMED, asset="a")
    assert n.notify_finding(f) is False


@pytest.mark.unit
def test_notifier_sends_on_confirmed_high(monkeypatch):
    posted = {}

    def fake_post(url, json=None, timeout=None):  # noqa: A002
        posted["url"] = url
        posted["body"] = json

    monkeypatch.setattr("httpx.post", fake_post)
    n = Notifier(slack_url="https://hooks.slack/x", enabled=True)
    f = Finding(title="RCE password: secret123", severity=Severity.CRITICAL,
                status=FindingStatus.CONFIRMED, asset="a")
    assert n.notify_finding(f) is True
    # Secret redacted in the message body.
    assert "secret123" not in json.dumps(posted["body"])


@pytest.mark.unit
def test_notifier_failure_non_fatal(monkeypatch):
    def boom(url, json=None, timeout=None):  # noqa: A002
        raise RuntimeError("network down")

    monkeypatch.setattr("httpx.post", boom)
    n = Notifier(discord_url="https://discord/x", enabled=True)
    f = Finding(title="X", severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED, asset="a")
    # Should not raise.
    assert n.notify_finding(f) is False
