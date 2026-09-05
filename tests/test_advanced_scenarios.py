"""Advanced, real-world end-to-end scenarios (QUARR).

Where the other suites test single tools or a single domain, these exercise the
*agent* across a full multi-phase engagement and the finding lifecycle state
machine — the parts that distinguish an autonomous agent from a script:

  1. Full Red attack chain: recon -> service enum -> SQLi (auto-creates a
     CRITICAL finding) driven by the real agent loop.
  2. Finding lifecycle state machine: legal/illegal transitions and
     auto-validation (observation -> ... -> confirmed) gated by evidence.
  3. Cross-domain pivot Red -> Blue: exploit found, then blue-team log analysis
     corroborates the attack and the source IP is blocked — one engagement.
  4. Policy resilience mid-chain: an out-of-scope / disallowed tool call is
     rejected but the agent recovers and still concludes.

The LLM is scripted and tool handlers are patched, so no real tools or network
are used; assertions target agent STATE (hosts, observations, findings, tool
history), which is the real contract.
"""

from pathlib import Path

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.models import (
    Engagement,
    Finding,
    FindingStatus,
    Observation,
    PentestState,
    Severity,
)
from quarr.core.validator import VALID_TRANSITIONS, FindingValidator

FIXTURES = Path(__file__).parent / "fixtures"


class ScriptedLLM:
    """Emits the scripted responses in order, then a default final answer."""

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


NMAP_DISCOVERY = "Nmap scan report for target.lab.local (10.10.10.20)\nHost is up (0.0012s latency).\nNmap done: 1 IP address (1 host up)"

NMAP_SERVICES = (
    "Nmap scan report for target.lab.local (10.10.10.20)\n"
    "PORT   STATE SERVICE VERSION\n"
    "22/tcp open  ssh     OpenSSH 8.9p1\n"
    "80/tcp open  http    Apache httpd 2.4.52\n"
)

SQLMAP_VULN = (
    "sqlmap identified the following injection point(s):\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "GET parameter 'id' is vulnerable.\n"
    "back-end DBMS: MySQL >= 5.6\n"
)


# ===========================================================================
# 1. Full Red attack chain through the real agent loop
# ===========================================================================

@pytest.mark.integration
async def test_full_attack_chain_recon_to_sqli(monkeypatch, sample_engagement):
    script = [
        _tc("network_discovery", target="10.10.10.20"),
        _tc("service_enumeration", target="10.10.10.20"),
        _tc("sqli_scan", target="http://10.10.10.20/product.php?id=1"),
        _final("Chain complete: SQL injection confirmed on product.php id parameter."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["network_discovery"], "handler", lambda **kw: NMAP_DISCOVERY)
    monkeypatch.setattr(reg["service_enumeration"], "handler", lambda **kw: NMAP_SERVICES)
    monkeypatch.setattr(reg["sqli_scan"], "handler", lambda **kw: SQLMAP_VULN)

    sample_engagement.allowed_operations = []  # allow all
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")

    result = await agent.run("Full pentest: discover, enumerate, test for SQLi")

    # Tools ran in order.
    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == ["network_discovery", "service_enumeration", "sqli_scan"]

    # Recon populated the host + services in state.
    host = agent.state.get_host("10.10.10.20")
    assert host is not None
    ports = {s.port for s in host.services}
    assert {22, 80} <= ports

    # SQLi auto-created a CRITICAL finding.
    sqli = [f for f in agent.state.findings if "sql injection" in f.title.lower()]
    assert sqli, "expected a SQL Injection finding"
    assert sqli[0].severity == Severity.CRITICAL
    assert "confirmed" in result.lower()


# ===========================================================================
# 2. Finding lifecycle state machine (the "advanced" correctness core)
# ===========================================================================

@pytest.mark.unit
class TestFindingLifecycle:
    def test_cannot_skip_from_observation_to_confirmed(self):
        f = Finding(title="XSS", asset="10.10.10.20", status=FindingStatus.OBSERVATION)
        assert FindingValidator.transition(f, FindingStatus.CONFIRMED) is False
        assert f.status == FindingStatus.OBSERVATION  # unchanged

    def test_legal_step_transition_raises_confidence(self):
        f = Finding(title="XSS", asset="10.10.10.20", status=FindingStatus.OBSERVATION)
        assert FindingValidator.transition(f, FindingStatus.HYPOTHESIS, "corroborated")
        assert f.status == FindingStatus.HYPOTHESIS
        assert f.confidence >= 0.3

    def test_dismissed_is_terminal(self):
        f = Finding(title="XSS", asset="10.10.10.20", status=FindingStatus.DISMISSED)
        assert VALID_TRANSITIONS[FindingStatus.DISMISSED] == []
        assert FindingValidator.transition(f, FindingStatus.HYPOTHESIS) is False

    def test_confirmation_autoenriches_cwe(self):
        # Drive a finding all the way to CONFIRMED and check CWE enrichment.
        f = Finding(title="SQL Injection", asset="10.10.10.20",
                    status=FindingStatus.VALIDATING, confidence=0.7,
                    evidence=["sqlmap: injectable", "manual: union works"])
        ok = FindingValidator.transition(f, FindingStatus.CONFIRMED, "sufficient evidence")
        assert ok and f.status == FindingStatus.CONFIRMED
        assert f.confidence >= 0.9
        # CWE reference enrichment (from knowledge base) should be attached.
        assert any(ref.upper().startswith("CWE") for ref in f.references)

    def test_auto_validate_advances_with_evidence(self):
        state = PentestState()
        state.engagement = Engagement(name="T", allowed_targets=["10.10.10.20"])
        # A DETECTED finding with >=2 evidence should advance to VALIDATING.
        f = Finding(title="SQL Injection on 10.10.10.20", asset="10.10.10.20",
                    status=FindingStatus.DETECTED, confidence=0.6,
                    evidence=["sqlmap says injectable", "500 error on quote"])
        state.add_finding(f)
        state.add_observation(Observation(
            source_tool="sqli_scan",
            description="SQLi scan on 10.10.10.20: VULNERABLE (params: id)"))
        actions = FindingValidator.auto_validate_findings(state)
        assert any("validating" in a for a in actions)
        assert f.status == FindingStatus.VALIDATING


# ===========================================================================
# 3. Cross-domain pivot: Red exploit -> Blue detection -> containment
# ===========================================================================

@pytest.mark.integration
async def test_red_to_blue_pivot_same_engagement(monkeypatch, sample_engagement):
    access_log = (FIXTURES / "apache_sqli_attack.log").read_text()

    script = [
        _tc("sqli_scan", target="http://10.10.10.20/product.php?id=1"),
        _tc("log_analysis", log_type="apache", filter_pattern="UNION"),
        _tc("firewall_block", ip_address="185.220.101.34"),
        _final("SQLi confirmed; attacker 185.220.101.34 seen in access log and blocked."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["sqli_scan"], "handler", lambda **kw: SQLMAP_VULN)
    monkeypatch.setattr(reg["log_analysis"], "handler", lambda **kw: access_log)
    monkeypatch.setattr(reg["firewall_block"], "handler",
                        lambda **kw: "✅ Blocked: 185.220.101.34")

    sample_engagement.allowed_operations = []
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama", session_role="operator")

    result = await agent.run("Exploit then hunt attacker traces and contain")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == ["sqli_scan", "log_analysis", "firewall_block"]
    # Red produced a CRITICAL SQLi finding...
    assert any(f.severity == Severity.CRITICAL for f in agent.state.findings)
    # ...and the blue-team + containment steps both executed successfully.
    assert all(t.success for t in agent.state.tool_history)
    assert "blocked" in result.lower()


# ===========================================================================
# 4. Policy resilience: a disallowed tool mid-chain is rejected, agent recovers
# ===========================================================================

@pytest.mark.integration
async def test_out_of_scope_call_rejected_then_agent_recovers(monkeypatch):
    # Scope allows only 10.10.10.0/24; the LLM first tries an out-of-scope host.
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"], allowed_operations=[])

    script = [
        _tc("network_discovery", target="8.8.8.8"),            # OUT OF SCOPE → rejected
        _tc("network_discovery", target="10.10.10.20"),        # in scope → runs
        _final("Recovered from scope violation; scanned the authorized host only."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))
    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["network_discovery"], "handler", lambda **kw: NMAP_DISCOVERY)

    agent = QuarrAgent(engagement=eng, backend="ollama", session_role="operator")
    result = await agent.run("Discover hosts")

    ran = [t.tool_name for t in agent.state.tool_history]
    # Only the in-scope discovery was actually executed/recorded.
    assert ran == ["network_discovery"]
    assert len(agent.state.tool_history) == 1
    # The out-of-scope target never made it into state.
    assert agent.state.get_host("8.8.8.8") is None
    assert agent.state.get_host("10.10.10.20") is not None
    assert "recovered" in result.lower()
