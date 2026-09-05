"""Real-world, multi-phase agent scenarios (QUARR) — the "intelligence" tier.

Where test_advanced_scenarios.py covers the core attack chain and the finding
state machine, this suite pushes the parts that make the agent *smart* rather
than a script, using realistic captured tool output as fixtures:

  1. Full recon -> content-discovery -> vuln-scan -> exploit chain, asserting
     the agent's PHASE DETECTION advances recon -> discovery -> vuln_scan ->
     exploit as the right tool categories run.
  2. Nuclei triage intelligence: a real multi-severity JSONL is parsed, sorted
     by severity, and only CRITICAL/HIGH auto-create findings (info/low/medium
     stay observations) — the agent must not cry wolf.
  3. Threat-intel enrichment escalation: an exploit finding is corroborated by
     a malicious-IOC verdict from the threat feed, and the same attacker IP is
     confirmed in the web access log and contained (Red -> Intel -> Blue).
  4. Deduplication across a noisy chain: two scanners report the SAME issue on
     the same asset; the dedup engine merges them into one finding while
     unioning evidence and keeping the highest severity/confidence.
  5. Resilience: three consecutive tool failures abort the loop cleanly with a
     partial state summary (Req 3.4) — the abort returns before recording the
     third execution, so tool_history holds the first two — never a crash.
  6. Idempotent recon: the agent re-running service enumeration on a known host
     must MERGE services (no duplicate ports), proving the world model is a set
     not a log.

The LLM is scripted and tool handlers are patched, so no real tools or network
are used; assertions target agent STATE and the intelligence primitives
(phase, dedup, validation), which are the real contract.
"""

from pathlib import Path

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.dedup import deduplicate
from quarr.core.models import (
    Finding,
    FindingStatus,
    Severity,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# Scripted LLM + helpers (same contract as the other scenario suites)
# --------------------------------------------------------------------------- #

class ScriptedLLM:
    """Emits scripted chat() responses in order, then a default final answer."""

    def __init__(self, script):
        self._script = list(script)

    async def chat(self, messages, tools=None, max_tokens=1024):
        if self._script:
            return self._script.pop(0)
        return {"content": "Assessment complete.", "tool_calls": [], "raw": {}}


def _tc(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}


def _final(text):
    return {"content": text, "tool_calls": [], "raw": {}}


# --------------------------------------------------------------------------- #
# Realistic canned tool output
# --------------------------------------------------------------------------- #

NMAP_DISCOVERY = (
    "Nmap scan report for target.lab.local (10.10.10.20)\n"
    "Host is up (0.0011s latency).\n"
    "Nmap done: 1 IP address (1 host up)"
)

NMAP_SERVICES = (
    "Nmap scan report for target.lab.local (10.10.10.20)\n"
    "PORT    STATE SERVICE VERSION\n"
    "22/tcp  open  ssh     OpenSSH 8.9p1\n"
    "80/tcp  open  http    Apache httpd 2.4.49\n"
    "443/tcp open  ssl/http Apache httpd 2.4.49\n"
    "Nmap done: 1 IP address (1 host up)\n"
)

# A second enum pass that also reports 3306 — should MERGE, not duplicate.
NMAP_SERVICES_RESCAN = (
    "Nmap scan report for target.lab.local (10.10.10.20)\n"
    "PORT     STATE SERVICE VERSION\n"
    "22/tcp   open  ssh     OpenSSH 8.9p1\n"
    "80/tcp   open  http    Apache httpd 2.4.49\n"
    "3306/tcp open  mysql   MySQL 5.7.40\n"
    "Nmap done: 1 IP address (1 host up)\n"
)

SQLMAP_VULN = (
    "sqlmap identified the following injection point(s):\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "GET parameter 'id' is vulnerable.\n"
    "back-end DBMS: MySQL >= 5.6\n"
)


# =========================================================================== #
# 1. Full recon -> discovery -> vuln -> exploit, tracking PHASE DETECTION
# =========================================================================== #

@pytest.mark.integration
async def test_phase_progression_recon_to_exploit(monkeypatch, sample_engagement):
    """The agent's _detect_phase must climb as each tool category runs."""
    nuclei = (FIXTURES / "nuclei_critical.jsonl").read_text()
    gobuster = (FIXTURES / "gobuster_admin.txt").read_text()

    script = [
        _tc("network_discovery", target="10.10.10.20"),
        _tc("service_enumeration", target="10.10.10.20", profile="basic"),
        _tc("web_content_discovery", target="http://10.10.10.20"),
        _tc("vulnerability_scan", target="http://10.10.10.20"),
        _tc("sqli_scan", target="http://10.10.10.20/product.php?id=1"),
        _final("Chain complete: recon, discovery, vuln scan and SQLi exploit done."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["network_discovery"], "handler", lambda **kw: NMAP_DISCOVERY)
    monkeypatch.setattr(reg["service_enumeration"], "handler", lambda **kw: NMAP_SERVICES)
    monkeypatch.setattr(reg["web_content_discovery"], "handler", lambda **kw: gobuster)
    monkeypatch.setattr(reg["vulnerability_scan"], "handler", lambda **kw: nuclei)
    monkeypatch.setattr(reg["sqli_scan"], "handler", lambda **kw: SQLMAP_VULN)

    sample_engagement.allowed_operations = []  # allow all
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")

    # Phase starts at recon before anything runs.
    assert agent._detect_phase() == "recon"

    result = await agent.run("Full assessment on 10.10.10.20")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == [
        "network_discovery", "service_enumeration",
        "web_content_discovery", "vulnerability_scan", "sqli_scan",
    ]
    # After an exploit-category tool ran, phase must have reached "exploit".
    assert agent._detect_phase() == "exploit"

    # The chain produced at least the SQLi CRITICAL plus the nuclei criticals.
    crit = [f for f in agent.state.findings if f.severity == Severity.CRITICAL]
    assert len(crit) >= 2
    assert any("sql injection" in f.title.lower() for f in agent.state.findings)
    assert "complete" in result.lower()


# =========================================================================== #
# 2. Nuclei triage: only CRITICAL/HIGH become findings, noise stays observation
# =========================================================================== #

@pytest.mark.integration
async def test_nuclei_triage_only_promotes_critical_high(monkeypatch, sample_engagement):
    nuclei = (FIXTURES / "nuclei_critical.jsonl").read_text()

    script = [
        _tc("vulnerability_scan", target="http://10.10.10.20"),
        _final("Vuln scan triaged."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))
    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["vulnerability_scan"], "handler", lambda **kw: nuclei)

    sample_engagement.allowed_operations = []
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")
    await agent.run("Scan http://10.10.10.20 for vulnerabilities")

    titles = {f.title for f in agent.state.findings}
    sevs = {f.severity for f in agent.state.findings}

    # The fixture has: 2 critical, 1 high, 1 medium, 1 low, 1 info.
    # Only critical + high are auto-promoted to findings.
    assert Severity.CRITICAL in sevs
    assert Severity.HIGH in sevs
    assert Severity.MEDIUM not in sevs, "medium must NOT auto-create a finding"
    assert Severity.LOW not in sevs, "low must NOT auto-create a finding"
    assert Severity.INFO not in sevs, "info must NOT auto-create a finding"

    # Exactly the 3 high-signal issues (2 critical + 1 high).
    assert len(agent.state.findings) == 3
    assert any("path traversal" in t.lower() for t in titles)
    assert any("git" in t.lower() for t in titles)


# =========================================================================== #
# 3. Threat-intel enrichment escalation: Red -> Intel -> Blue
# =========================================================================== #

@pytest.mark.integration
async def test_threat_intel_corroborates_attacker_and_contains(monkeypatch, sample_engagement):
    access_log = (FIXTURES / "apache_sqli_attack.log").read_text()
    malicious_verdict = (
        "=== THREAT INTEL: ip = 185.220.101.34 ===\n\n"
        "=== ABUSEIPDB: 185.220.101.34 ===\n"
        "Abuse Score: 100%\n"
        "Total Reports: 4213\n"
        "Country: DE\n"
        "\n🚨 HIGH RISK — Abuse score 100%\n"
        "--- Checked 1 source(s) ---"
    )

    script = [
        _tc("sqli_scan", target="http://10.10.10.20/product.php?id=1"),
        _tc("log_analysis", log_type="apache", filter_pattern="UNION"),
        _tc("threat_feed_check", ioc_type="ip", value="185.220.101.34"),
        _tc("firewall_block", ip_address="185.220.101.34"),
        _final(
            "SQLi confirmed. Attacker 185.220.101.34 (AbuseIPDB 100%) seen in "
            "access log exfiltrating via UNION SELECT, and now blocked."
        ),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["sqli_scan"], "handler", lambda **kw: SQLMAP_VULN)
    monkeypatch.setattr(reg["log_analysis"], "handler", lambda **kw: access_log)
    monkeypatch.setattr(reg["threat_feed_check"], "handler", lambda **kw: malicious_verdict)
    monkeypatch.setattr(reg["firewall_block"], "handler",
                        lambda **kw: "✅ Blocked: 185.220.101.34")

    sample_engagement.allowed_operations = []
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")

    result = await agent.run("Exploit, enrich attacker IP with threat intel, then contain")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == ["sqli_scan", "log_analysis", "threat_feed_check", "firewall_block"]
    # Every step succeeded and the full cross-domain chain reached a conclusion.
    assert all(t.success for t in agent.state.tool_history)
    # Red produced the CRITICAL SQLi finding.
    assert any(f.severity == Severity.CRITICAL for f in agent.state.findings)
    # The threat-intel verdict was recorded as an observation.
    assert any(o.source_tool == "threat_feed_check" for o in agent.state.observations)
    assert "blocked" in result.lower() and "185.220.101.34" in result


# =========================================================================== #
# 4. Deduplication across a noisy multi-scanner chain
# =========================================================================== #

@pytest.mark.integration
class TestDeduplicationIntelligence:
    def test_two_scanners_same_issue_merge_to_one(self):
        state_findings = [
            Finding(
                title="SQL Injection",
                asset="10.10.10.20",
                severity=Severity.HIGH,
                confidence=0.6,
                status=FindingStatus.DETECTED,
                evidence=["nuclei: sqli template matched"],
                references=["CWE-89"],
            ),
            Finding(
                title="sql injection",  # different case → same normalized key
                asset="10.10.10.20",
                severity=Severity.CRITICAL,  # higher severity should win
                confidence=0.9,
                status=FindingStatus.CONFIRMED,
                evidence=["sqlmap: injectable id parameter"],
                references=["CWE-89"],
            ),
            Finding(
                title="Missing HSTS Header",  # unrelated → must NOT merge
                asset="10.10.10.20",
                severity=Severity.LOW,
                confidence=0.5,
            ),
        ]

        class _S:
            findings = state_findings

        state = _S()
        report = deduplicate(state, dry_run=False)

        # One merge happened (two SQLi → one), HSTS untouched.
        assert report.merged == 1
        assert len(state.findings) == 2

        sqli = next(f for f in state.findings if "sql injection" in f.title.lower())
        # Highest severity + confidence survive.
        assert sqli.severity == Severity.CRITICAL
        assert sqli.confidence == 0.9
        # Evidence from BOTH scanners is unioned onto the survivor.
        assert any("nuclei" in e for e in sqli.evidence)
        assert any("sqlmap" in e for e in sqli.evidence)

    def test_dedup_is_idempotent(self):
        findings = [
            Finding(title="XSS", asset="a", severity=Severity.MEDIUM, references=["CWE-79"]),
            Finding(title="xss", asset="a", severity=Severity.MEDIUM, references=["CWE-79"]),
        ]

        class _S:
            pass

        state = _S()
        state.findings = findings
        first = deduplicate(state)
        assert first.merged == 1 and len(state.findings) == 1
        # Running again changes nothing.
        second = deduplicate(state)
        assert second.merged == 0 and len(state.findings) == 1


# =========================================================================== #
# 5. Resilience: three consecutive tool failures abort cleanly
# =========================================================================== #

@pytest.mark.integration
async def test_three_consecutive_failures_abort_with_partial_state(
    monkeypatch, sample_engagement
):
    # LLM keeps trying different tools; every handler errors out.
    script = [
        _tc("service_enumeration", target="10.10.10.20", profile="basic"),
        _tc("web_content_discovery", target="http://10.10.10.20"),
        _tc("vulnerability_scan", target="http://10.10.10.20"),
        _final("should not be reached — loop aborts first"),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["service_enumeration"], "handler",
                        lambda **kw: "[ERROR] nmap: host unreachable")
    monkeypatch.setattr(reg["web_content_discovery"], "handler",
                        lambda **kw: "[ERROR] gobuster: connection refused")
    monkeypatch.setattr(reg["vulnerability_scan"], "handler",
                        lambda **kw: "[TIMEOUT] nuclei exceeded 600s")

    sample_engagement.allowed_operations = []
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")

    result = await agent.run("Scan the host thoroughly")

    # The loop aborts on the 3rd consecutive failure (Req 3.4). That final
    # failing execution is NOT recorded — the abort returns before record_tool —
    # so exactly the first two failures land in tool_history.
    assert len(agent.state.tool_history) == 2
    assert all(not t.success for t in agent.state.tool_history)
    # The abort message reports 3 consecutive failures and a partial summary.
    assert "halted" in result.lower()
    assert "3 consecutive tool failures" in result
    # It still returns a state summary, not a crash.
    assert "ENGAGEMENT" in result


# =========================================================================== #
# 6. Idempotent recon: re-enumeration MERGES services, never duplicates ports
# =========================================================================== #

@pytest.mark.integration
async def test_reenumeration_merges_services_no_duplicate_ports(
    monkeypatch, sample_engagement
):
    call_count = {"n": 0}

    def _svc_handler(**kw):
        call_count["n"] += 1
        return NMAP_SERVICES if call_count["n"] == 1 else NMAP_SERVICES_RESCAN

    script = [
        _tc("service_enumeration", target="10.10.10.20", profile="basic"),
        _tc("service_enumeration", target="10.10.10.20", profile="service_detection"),
        _final("Re-enumeration merged."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))
    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["service_enumeration"], "handler", _svc_handler)

    sample_engagement.allowed_operations = []
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")

    await agent.run("Enumerate then re-enumerate services on 10.10.10.20")

    host = agent.state.get_host("10.10.10.20")
    assert host is not None
    ports = sorted(s.port for s in host.services)
    # First pass: 22,80,443. Second pass adds 3306 (22,80 dedup). No duplicates.
    assert ports == [22, 80, 443, 3306]
    assert len(ports) == len(set(ports)), "world model must not contain duplicate ports"
