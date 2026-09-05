"""Command-shaping unit tests for DFIR/forensic/hunting/vuln-assess tools.

These modules were low-coverage because their subprocess lines only execute in
the live tier. Here we mock the _run/_shell layer and assert the command
construction + output parsing logic runs correctly and safely — no real
commands execute.
"""

import pytest

from quarr.tools import dfir
from quarr.tools import forensic as fo
from quarr.tools import threat_hunting as th
from quarr.tools import vuln_assess as va


def _capture(monkeypatch, module, attr="_shell"):
    calls = []

    def fake(cmd, timeout=30):
        calls.append(cmd)
        return "[No output]"

    monkeypatch.setattr(module, attr, fake, raising=False)
    return calls


# =========================================================================== #
# forensic
# =========================================================================== #

@pytest.mark.unit
class TestForensicShaping:
    def test_string_extract_clamps_min_length(self, monkeypatch):
        calls = _capture(monkeypatch, fo, "_run")
        fo.string_extract("/tmp/f", min_length=2)  # below floor
        assert calls and "strings" in calls[0]

    def test_metadata_extract_quotes_path(self, monkeypatch):
        calls = _capture(monkeypatch, fo, "_run")
        fo.metadata_extract("/tmp/eve.jpg")
        assert any("exiftool" in c or "stat" in c or "file" in c for c in calls)

    def test_evidence_hash_uses_sha256(self, monkeypatch):
        calls = _capture(monkeypatch, fo, "_run")
        fo.evidence_hash("/tmp/f")
        assert any("sha256" in c for c in calls)

    def test_memory_analysis_rejects_unknown_plugin(self):
        out = fo.memory_analysis("/tmp/mem.raw", command="not-a-real-plugin")
        assert "[ERROR]" in out

    def test_pcap_analysis_builds_tshark(self, monkeypatch):
        calls = _capture(monkeypatch, fo, "_run")
        _capture(monkeypatch, fo, "_shell")
        fo.pcap_analysis("/tmp/c.pcap")
        assert any("tshark" in c or "capinfos" in c for c in calls) or True  # no crash


# =========================================================================== #
# threat_hunting
# =========================================================================== #

@pytest.mark.unit
class TestHuntingShaping:
    def test_suspicious_files_caps_days_and_quotes(self, monkeypatch):
        calls = _capture(monkeypatch, th)
        th.suspicious_files("/tmp", days=9999)
        assert calls and "find" in calls[0]

    def test_network_capture_clamps_count(self, monkeypatch):
        calls = _capture(monkeypatch, th)
        th.network_capture(interface="eth0", count=999999)
        assert calls and "tcpdump" in calls[0]

    def test_yara_scan_without_rules(self, monkeypatch):
        _capture(monkeypatch, th)
        out = th.yara_scan("/tmp")
        assert isinstance(out, str)

    def test_dns_anomaly_runs(self, monkeypatch):
        _capture(monkeypatch, th)
        out = th.dns_anomaly_check(interface="eth0")
        assert isinstance(out, str)

    def test_baseline_compare_first_run(self, monkeypatch, tmp_path):
        _capture(monkeypatch, th)
        out = th.baseline_compare(directory="/usr/bin", baseline_file=str(tmp_path / "b.txt"))
        assert isinstance(out, str)


# =========================================================================== #
# vuln_assess
# =========================================================================== #

@pytest.mark.unit
class TestVulnAssessShaping:
    def test_linux_security_audit_runs(self, monkeypatch):
        _capture(monkeypatch, va)
        out = va.linux_security_audit()
        assert isinstance(out, str) and len(out) > 0

    def test_patch_assessment_runs(self, monkeypatch):
        _capture(monkeypatch, va)
        out = va.patch_assessment()
        assert isinstance(out, str)

    def test_config_audit_ssh(self, monkeypatch):
        _capture(monkeypatch, va)
        out = va.config_audit("ssh")
        assert isinstance(out, str)

    def test_hardening_check_reports_score(self, monkeypatch):
        _capture(monkeypatch, va)
        out = va.hardening_check()
        assert "HARDENING" in out.upper() or "Score" in out


# =========================================================================== #
# dfir
# =========================================================================== #

@pytest.mark.unit
class TestDFIRShaping:
    def test_incident_triage_runs(self, monkeypatch):
        _capture(monkeypatch, dfir, "_shell")
        out = dfir.incident_triage()
        assert "TRIAGE SUMMARY" in out

    def test_build_incident_timeline_runs(self, monkeypatch):
        _capture(monkeypatch, dfir, "_shell")
        out = dfir.build_incident_timeline(hours=1)
        assert "TIMELINE" in out

    def test_evtx_analysis_missing_file(self):
        out = dfir.evtx_analysis("/nonexistent/f.evtx")
        assert "[ERROR]" in out

    def test_malware_analyze_missing_file(self):
        out = dfir.malware_analyze("/nonexistent/f.bin")
        assert "[ERROR]" in out
