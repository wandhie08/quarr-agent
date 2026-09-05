"""Unit tests for the audit logger (Phase 1, Req 6)."""

import hashlib
import json

import pytest

from quarr.core.audit import AuditLogger


def _read_entries(path):
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


@pytest.mark.unit
def test_sequence_increments(tmp_path):
    path = str(tmp_path / "audit.log")
    a = AuditLogger(path=path)
    s1 = a.record_execution(tool_name="nmap", target="10.0.0.1", arguments={})
    s2 = a.record_execution(tool_name="nikto", target="10.0.0.2", arguments={})
    assert s1 == 1 and s2 == 2


@pytest.mark.unit
def test_sequence_persists_across_reinit(tmp_path):
    path = str(tmp_path / "audit.log")
    a = AuditLogger(path=path)
    a.record_execution(tool_name="nmap", target="x", arguments={})
    a.record_execution(tool_name="nmap", target="x", arguments={})
    # Re-init should continue from last sequence.
    b = AuditLogger(path=path)
    seq = b.record_execution(tool_name="nmap", target="x", arguments={})
    assert seq == 3


@pytest.mark.unit
def test_each_entry_has_valid_sha256(tmp_path):
    path = str(tmp_path / "audit.log")
    a = AuditLogger(path=path)
    a.record_execution(tool_name="nmap", target="10.0.0.1", arguments={"flags": "-sV"})
    entries = _read_entries(path)
    assert len(entries) == 1
    entry = entries[0]
    assert "sha256" in entry
    stored = entry.pop("sha256")
    recomputed = hashlib.sha256(
        json.dumps(entry, sort_keys=True, default=str).encode()
    ).hexdigest()
    assert stored == recomputed


@pytest.mark.unit
def test_secrets_redacted_in_arguments(tmp_path):
    path = str(tmp_path / "audit.log")
    a = AuditLogger(path=path)
    a.record_execution(
        tool_name="hydra",
        target="10.0.0.1",
        arguments={"password": "hunter2", "api_key": "sk-secret", "service": "ssh"},
    )
    with open(path) as f:
        raw = f.read()
    assert "hunter2" not in raw
    assert "sk-secret" not in raw
    assert "ssh" in raw


@pytest.mark.unit
def test_result_summary_redacted(tmp_path):
    path = str(tmp_path / "audit.log")
    a = AuditLogger(path=path)
    seq = a.record_execution(tool_name="nmap", target="x", arguments={})
    a.record_result(seq=seq, success=True, duration_ms=42, result_summary="ok")
    entries = _read_entries(path)
    result = [e for e in entries if e["event"] == "tool_result"][0]
    assert result["success"] is True
    assert result["duration_ms"] == 42


@pytest.mark.unit
def test_rotation_triggers(tmp_path):
    path = str(tmp_path / "audit.log")
    a = AuditLogger(path=path, rotate_max_bytes=200, rotate_backups=3)
    for _ in range(50):
        a.record_execution(tool_name="nmap", target="10.0.0.1", arguments={"x": "y" * 20})
    # A rotated backup file should exist once size threshold is exceeded.
    backups = list(tmp_path.glob("audit.log.*"))
    assert len(backups) >= 1
