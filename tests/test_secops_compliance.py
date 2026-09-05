"""Tests for secops compliance reporting & health scoring (professional-readiness fixes).

Locks in the audit fixes:
  - PCI report never reports untested controls as passing (no fake ✅); such
    controls are flagged MANUAL REVIEW and excluded from the score denominator.
  - HIPAA framework is implemented (was documented but returned "unknown").
  - security_health_check score derives from the real hardening percentage
    (no arbitrary ×10 penalty that saturates to 0) and subtracts for active
    threats.
"""

import pytest

from quarr.tools import secops as so


@pytest.mark.unit
class TestComplianceReport:
    def test_pci_has_no_fake_passing_placeholders(self, monkeypatch):
        # Force all automated checks to fail so any ✅ could only come from a
        # hardcoded placeholder — there must be none.
        monkeypatch.setattr("quarr.tools.blue_team.firewall_status", lambda: "inactive")
        monkeypatch.setattr("quarr.tools.vuln_assess.config_audit", lambda s="all": "PermitRootLogin yes")
        monkeypatch.setattr("os.path.exists", lambda p: False)

        out = so.compliance_report("pci")
        assert "✅" not in out                       # nothing falsely passes
        assert "MANUAL REVIEW REQUIRED" in out
        assert "Score (automated checks only): 0/3" in out
        # The old placeholder wording must be gone.
        assert "Req 4: Encryption" not in out

    def test_pci_counts_real_passes(self, monkeypatch):
        monkeypatch.setattr("quarr.tools.blue_team.firewall_status", lambda: "Status: active")
        monkeypatch.setattr("quarr.tools.vuln_assess.config_audit", lambda s="all": "PermitRootLogin no")
        monkeypatch.setattr("os.path.exists", lambda p: True)
        out = so.compliance_report("pci")
        assert "Score (automated checks only): 3/3" in out

    def test_hipaa_is_implemented(self, monkeypatch):
        monkeypatch.setattr("quarr.tools.blue_team.firewall_status", lambda: "inactive")
        monkeypatch.setattr("quarr.tools.vuln_assess.config_audit", lambda s="all": "")
        monkeypatch.setattr("os.path.exists", lambda p: False)
        out = so.compliance_report("hipaa")
        assert "HIPAA SECURITY RULE" in out
        assert "MANUAL REVIEW REQUIRED" in out
        assert "[ERROR]" not in out

    def test_unknown_framework_errors(self):
        out = so.compliance_report("sox")
        assert "[ERROR]" in out and "Available: cis, pci, hipaa" in out

    def test_cis_framework_runs(self, monkeypatch):
        monkeypatch.setattr("quarr.tools.vuln_assess.linux_security_audit", lambda: "AUDIT")
        monkeypatch.setattr("quarr.tools.vuln_assess.hardening_check", lambda: "HARDEN")
        out = so.compliance_report("cis")
        assert "CIS BENCHMARK COMPLIANCE" in out


@pytest.mark.unit
class TestHealthScore:
    def _patch(self, monkeypatch, hardening_out, conns="No suspicious", procs="clean"):
        monkeypatch.setattr("quarr.tools.vuln_assess.hardening_check", lambda: hardening_out)
        monkeypatch.setattr("quarr.tools.vuln_assess.patch_assessment", lambda: "patches ok")
        monkeypatch.setattr("quarr.tools.blue_team.active_connections", lambda ft="all": conns)
        monkeypatch.setattr("quarr.tools.blue_team.process_monitor", lambda **k: procs)

    def test_score_tracks_hardening_percentage(self, monkeypatch):
        self._patch(monkeypatch, "=== HARDENING ===\nScore: 7/9 (78%)\n")
        out = so.security_health_check()
        assert "OVERALL SCORE: 78/100" in out
        assert "hardening baseline 78%" in out
        assert "🟡 NEEDS ATTENTION" in out

    def test_active_threats_reduce_score(self, monkeypatch):
        # 90% hardening but a suspicious connection AND process → 90 - 2*20 = 50.
        self._patch(
            monkeypatch,
            "Score: 9/10 (90%)\n",
            conns="ESTAB 10.0.0.5:4444 evil:1337",   # not "No suspicious"
            procs="=== SUSPICIOUS PROCESSES ===\nnc -e",
        )
        out = so.security_health_check()
        assert "OVERALL SCORE: 50/100" in out
        assert "2 active threat(s)" in out

    def test_high_hardening_no_threats_is_healthy(self, monkeypatch):
        self._patch(monkeypatch, "Score: 9/9 (100%)\n")
        out = so.security_health_check()
        assert "OVERALL SCORE: 100/100" in out
        assert "🟢 HEALTHY" in out

    def test_score_never_negative(self, monkeypatch):
        self._patch(
            monkeypatch, "Score: 0/9 (0%)\n",
            conns="ESTAB evil:4444", procs="=== SUSPICIOUS PROCESSES ===",
        )
        out = so.security_health_check()
        assert "OVERALL SCORE: 0/100" in out
