"""Unit tests for quarr.tools.threat_intel.

These exercise the IOC-enrichment parsing logic without any network access by
mocking the module-level `_http_get`. They also lock in the "API key missing"
and "malformed response" branches. This module was previously excluded from the
coverage report; these tests give it real coverage.
"""

import json

import pytest

from quarr.tools import threat_intel as ti


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Guard: fail loudly if any test hits the real _http_get."""
    def _boom(*a, **k):  # pragma: no cover - only triggers on a test bug
        raise AssertionError("network access attempted; mock _http_get in the test")
    monkeypatch.setattr(ti, "_http_get", _boom)


def _patch_http(monkeypatch, payload):
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    monkeypatch.setattr(ti, "_http_get", lambda *a, **k: raw)


# --------------------------- API key gating --------------------------------- #

@pytest.mark.unit
def test_virustotal_requires_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    out = ti.virustotal_lookup("hash", "abc123")
    assert "[ERROR]" in out and "VIRUSTOTAL_API_KEY" in out


@pytest.mark.unit
def test_abuseipdb_requires_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    out = ti.abuseipdb_check("1.2.3.4")
    assert "[ERROR]" in out and "ABUSEIPDB_API_KEY" in out


@pytest.mark.unit
def test_shodan_requires_api_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    out = ti.shodan_lookup("1.2.3.4")
    assert "[ERROR]" in out and "SHODAN_API_KEY" in out


# --------------------------- VirusTotal parsing ----------------------------- #

@pytest.mark.unit
def test_virustotal_hash_malicious(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    _patch_http(monkeypatch, {
        "data": {"attributes": {
            "last_analysis_stats": {"malicious": 12, "harmless": 60, "undetected": 8},
            "type_description": "Win32 EXE",
            "meaningful_name": "evil.exe",
            "size": 1024,
            "tags": ["trojan", "packed"],
        }}
    })
    out = ti.virustotal_lookup("hash", "deadbeef")
    assert "VIRUSTOTAL" in out
    assert "12/80" in out            # malicious / total
    assert "MALICIOUS" in out
    assert "trojan" in out


@pytest.mark.unit
def test_virustotal_unknown_type(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    # No network expected: the type check returns before _http_get.
    out = ti.virustotal_lookup("banana", "x")
    assert "[ERROR]" in out and "Unknown type" in out


@pytest.mark.unit
def test_virustotal_malformed_json(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    _patch_http(monkeypatch, "not-json")
    out = ti.virustotal_lookup("ip", "1.2.3.4")
    assert "[ERROR]" in out


# --------------------------- AbuseIPDB parsing ------------------------------ #

@pytest.mark.unit
@pytest.mark.parametrize("score,marker", [(90, "HIGH RISK"), (30, "MODERATE RISK"), (5, "LOW RISK")])
def test_abuseipdb_risk_bands(monkeypatch, score, marker):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    _patch_http(monkeypatch, {"data": {
        "abuseConfidenceScore": score, "totalReports": 3, "countryCode": "US",
        "isp": "X", "domain": "x.com", "usageType": "hosting", "isWhitelisted": False,
    }})
    out = ti.abuseipdb_check("1.2.3.4")
    assert "ABUSEIPDB" in out
    assert f"{score}%" in out
    assert marker in out


# --------------------------- CVE lookup ------------------------------------- #

@pytest.mark.unit
def test_cve_lookup_requires_input():
    out = ti.cve_lookup()
    assert "[ERROR]" in out


@pytest.mark.unit
def test_cve_lookup_parses_cvss(monkeypatch):
    _patch_http(monkeypatch, {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Log4Shell RCE"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 10.0, "baseSeverity": "CRITICAL",
            "vectorString": "CVSS:3.1/AV:N",
        }}]},
    }}]})
    out = ti.cve_lookup(cve_id="cve-2021-44228")
    assert "CVE-2021-44228" in out
    assert "10.0" in out and "CRITICAL" in out
    assert "Log4Shell" in out


@pytest.mark.unit
def test_cve_lookup_no_results(monkeypatch):
    _patch_http(monkeypatch, {"vulnerabilities": []})
    out = ti.cve_lookup(keyword="nonexistent widget")
    assert "No CVE found" in out
