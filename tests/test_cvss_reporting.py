"""Tests for CVSS v3.1 calculator and the bug-bounty report generator."""

import pytest

from quarr.core.cvss import base_score, score_finding, severity_of, suggest_vector
from quarr.core.models import Engagement, Finding, FindingStatus, PentestState, Severity
from quarr.core.reporter import generate_bug_bounty_report


@pytest.mark.unit
class TestCVSS:
    @pytest.mark.parametrize("vector,expected", [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # network RCE-ish
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),   # high-complexity info leak
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),   # local privesc
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope-changed RCE
    ])
    def test_base_score_matches_first_org(self, vector, expected):
        assert abs(base_score(vector) - expected) < 0.05

    def test_severity_mapping(self):
        assert severity_of(0.0) == "none"
        assert severity_of(3.9) == "low"
        assert severity_of(6.9) == "medium"
        assert severity_of(8.9) == "high"
        assert severity_of(9.8) == "critical"

    def test_invalid_vector_raises(self):
        with pytest.raises(ValueError):
            base_score("not-a-vector")
        with pytest.raises(ValueError):
            base_score("CVSS:3.1/AV:N/AC:L")  # missing metrics

    def test_suggest_vector_known_types(self):
        assert suggest_vector("sql-injection")
        assert suggest_vector("bola")
        assert suggest_vector("unknown-type") is None

    def test_score_finding_by_type(self):
        r = score_finding("sql-injection")
        assert r["score"] > 9.0 and r["severity"] == "critical"
        assert r["vector"].startswith("CVSS:3.1/")

    def test_score_finding_explicit_vector_overrides_type(self):
        r = score_finding("xss", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert r["score"] == 10.0

    def test_score_finding_empty_when_unknown(self):
        assert score_finding("totally-unknown") == {}


@pytest.mark.unit
class TestBugBountyReport:
    def _state(self):
        st = PentestState()
        st.engagement = Engagement(name="BB Test", allowed_targets=["target.com"])
        st.add_finding(Finding(
            title="SQL Injection on /product?id=1", asset="target.com",
            severity=Severity.CRITICAL, status=FindingStatus.CONFIRMED,
            description="Injectable id parameter", evidence=["sqlmap: injectable", "DBMS: MySQL"],
            remediation="Use parameterized queries.", references=["CWE-89"]))
        st.add_finding(Finding(
            title="Reflected XSS in search", asset="target.com",
            severity=Severity.MEDIUM, status=FindingStatus.CONFIRMED))
        return st

    def test_report_has_cvss_and_sections(self):
        report = generate_bug_bounty_report(self._state())
        assert "CVSS v3.1:" in report
        assert "CVSS:3.1/AV:N" in report  # a vector string is present
        assert "### Steps to Reproduce" in report
        assert "### Impact" in report
        assert "### Remediation" in report
        assert "CWE-89" in report

    def test_findings_sorted_severe_first(self):
        report = generate_bug_bounty_report(self._state())
        # SQLi (9.8) must appear before XSS (6.1).
        assert report.index("SQL Injection") < report.index("Reflected XSS")

    def test_empty_state(self):
        st = PentestState()
        st.engagement = Engagement(name="Empty", allowed_targets=["x"])
        assert "No findings recorded" in generate_bug_bounty_report(st)
