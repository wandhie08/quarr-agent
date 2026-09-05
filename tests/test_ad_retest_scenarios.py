"""Real-world Active Directory & Retest-lifecycle scenarios (QUARR).

Closes two coverage gaps that had no agent-driven scenario:

  ACTIVE DIRECTORY  (quarr/tools/active_directory.py, ad_attack/ad_enum tools)
    1. Full AD kill chain through the real agent loop:
         ldap_search (enum, LOW)
           -> kerberos_asrep_roast (AS-REP, HIGH)
             -> secrets_dump (NTDS/DCSync, CRITICAL)
               -> psexec (lateral movement, CRITICAL)
       Verifies role-gating (CRITICAL tools need `admin`), tool ordering, and
       that every impacket step is recorded as a successful observation.
    2. Role enforcement: an `operator` session is REJECTED for a CRITICAL AD
       tool (secrets_dump) but the agent recovers and finishes with the
       lower-risk enumeration it is allowed to run.

  RETEST LIFECYCLE  (quarr/core/retest.py, M18)
    3. suggest_retest_tools maps finding types -> the right verification tool
       (SQLi, weak-credentials, APK manifest/secrets, and the generic fallback).
    4. mark_retest_result drives the lifecycle: a remediated finding is
       DISMISSED with lowered confidence; a still-vulnerable one stays and
       gains retest evidence. retest_summary reflects both.

LLM is scripted and handlers patched — no real impacket/network. Assertions
target agent STATE and the retest primitives (the real contract).
"""

from pathlib import Path

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.exceptions import PolicyViolationError
from quarr.core.models import (
    Engagement,
    Finding,
    FindingStatus,
    PentestState,
    Severity,
)
from quarr.core.retest import (
    get_retestable_findings,
    mark_retest_result,
    retest_summary,
    suggest_retest_tools,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# Scripted LLM helpers
# --------------------------------------------------------------------------- #

class ScriptedLLM:
    def __init__(self, script):
        self._script = list(script)

    async def chat(self, messages, tools=None, max_tokens=1024):
        if self._script:
            return self._script.pop(0)
        return {"content": "AD assessment complete.", "tool_calls": [], "raw": {}}


def _tc(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}


def _final(text):
    return {"content": text, "tool_calls": [], "raw": {}}


def _ad_agent(script, monkeypatch, *, role):
    eng = Engagement(
        name="AD Lab",
        allowed_targets=["10.10.10.0/24", "dc01.corp.local"],
        allowed_operations=[],  # allow all registered tools
    )
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))
    agent = QuarrAgent(engagement=eng, backend="ollama", session_role=role)
    agent.client = ScriptedLLM(script)
    return agent


# --------------------------------------------------------------------------- #
# Realistic canned impacket / AD tool output
# --------------------------------------------------------------------------- #

LDAP_USERS = (
    "sAMAccountName: Administrator\n"
    "sAMAccountName: krbtgt\n"
    "sAMAccountName: jsmith\n"
    "  memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local\n"
    "sAMAccountName: svc_sql\n"
)

ASREP_HASH = (
    "$krb5asrep$23$jsmith@CORP.LOCAL:"
    "a1b2c3d4e5f60718$9a8b7c6d5e4f30211223344556677889"
)


# =========================================================================== #
# 1. Full AD kill chain (admin role) through the real agent loop
# =========================================================================== #

@pytest.mark.integration
async def test_full_ad_kill_chain(monkeypatch):
    secretsdump = (FIXTURES / "impacket_secretsdump.txt").read_text()

    script = [
        _tc("ldap_search", target="10.10.10.10"),
        _tc("kerberos_asrep_roast", target="10.10.10.10", domain="corp.local"),
        _tc("secrets_dump", target="10.10.10.10", username="Administrator",
            password="P@ssw0rd", domain="corp.local"),
        _tc("psexec", target="10.10.10.11", username="Administrator",
            password="P@ssw0rd", domain="corp.local", command="whoami"),
        _final("AD compromised: DCSync dumped krbtgt; lateral move to WKS confirmed."),
    ]
    # CRITICAL tools (secrets_dump/psexec) require the admin role.
    agent = _ad_agent(script, monkeypatch, role="admin")

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["ldap_search"], "handler", lambda **kw: LDAP_USERS)
    monkeypatch.setattr(reg["kerberos_asrep_roast"], "handler", lambda **kw: ASREP_HASH)
    monkeypatch.setattr(reg["secrets_dump"], "handler", lambda **kw: secretsdump)
    monkeypatch.setattr(reg["psexec"], "handler", lambda **kw: "corp\\administrator")

    result = await agent.run("Own the domain: enumerate, roast, DCSync, then move laterally")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == ["ldap_search", "kerberos_asrep_roast", "secrets_dump", "psexec"]
    # Every impacket step executed successfully.
    assert all(t.success for t in agent.state.tool_history)
    # Each AD tool recorded an observation (generic handler path).
    obs_tools = {o.source_tool for o in agent.state.observations}
    assert {"ldap_search", "kerberos_asrep_roast", "secrets_dump", "psexec"} <= obs_tools
    assert "lateral" in result.lower() or "dcsync" in result.lower()


# =========================================================================== #
# 2. Role enforcement: operator is denied a CRITICAL AD tool, then recovers
# =========================================================================== #

@pytest.mark.integration
async def test_operator_denied_critical_ad_tool_then_recovers(monkeypatch):
    script = [
        _tc("secrets_dump", target="10.10.10.10", username="Administrator",
            password="P@ssw0rd", domain="corp.local"),   # CRITICAL → denied for operator
        _tc("ldap_search", target="10.10.10.10"),          # LOW → allowed, runs
        _final("Recovered: lacked privilege for DCSync, completed LDAP enumeration."),
    ]
    agent = _ad_agent(script, monkeypatch, role="operator")

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["secrets_dump"], "handler", lambda **kw: "SHOULD NOT RUN")
    monkeypatch.setattr(reg["ldap_search"], "handler", lambda **kw: LDAP_USERS)

    result = await agent.run("Try to DCSync, otherwise enumerate")

    ran = [t.tool_name for t in agent.state.tool_history]
    # The CRITICAL tool was policy-rejected before execution; only LDAP ran.
    assert ran == ["ldap_search"]
    assert agent.state.tool_history[0].success
    assert "recovered" in result.lower()

    # Sanity: the policy engine really does deny operator for a CRITICAL tool.
    from quarr.core.policy import PolicyEngine
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize(
            "secrets_dump",
            {"target": "10.10.10.10"},
            agent.state.engagement,
            role="operator",
            tool_risk=reg["secrets_dump"].risk,
        )


# =========================================================================== #
# 3. suggest_retest_tools maps finding type -> verification tool
# =========================================================================== #

@pytest.mark.unit
class TestSuggestRetestTools:
    def test_sqli_maps_to_sqli_scan(self):
        f = Finding(title="SQL Injection on 10.10.10.20", asset="http://10.10.10.20/p?id=1")
        sug = suggest_retest_tools(f)
        assert sug[0]["tool"] == "sqli_scan"
        assert sug[0]["args"]["target"] == f.asset

    def test_weak_credentials_maps_to_bruteforce(self):
        f = Finding(title="Weak credentials on 10.10.10.20 (ssh)", asset="10.10.10.20")
        tools = [s["tool"] for s in suggest_retest_tools(f)]
        assert "bruteforce_login" in tools

    def test_apk_manifest_maps_to_manifest_analysis(self):
        f = Finding(title="Android Manifest: debuggable=true", asset="/tmp/apk")
        tools = [s["tool"] for s in suggest_retest_tools(f)]
        assert "apk_manifest_analysis" in tools

    def test_hardcoded_secret_maps_to_secrets_scan(self):
        f = Finding(title="Hardcoded Secrets in APK Source", asset="/tmp/apk-src")
        tools = [s["tool"] for s in suggest_retest_tools(f)]
        assert "apk_secrets_scan" in tools

    def test_unknown_type_falls_back_to_vuln_scan(self):
        f = Finding(title="Some obscure misconfiguration", asset="10.10.10.20")
        sug = suggest_retest_tools(f)
        assert sug == [{"tool": "vulnerability_scan", "args": {"target": "10.10.10.20"}}]


# =========================================================================== #
# 4. mark_retest_result lifecycle + retest_summary
# =========================================================================== #

@pytest.mark.unit
class TestRetestLifecycle:
    def _state_with_findings(self):
        state = PentestState()
        state.engagement = Engagement(name="T", allowed_targets=["10.10.10.20"])
        state.add_finding(Finding(
            title="SQL Injection on 10.10.10.20", asset="10.10.10.20",
            severity=Severity.CRITICAL, status=FindingStatus.CONFIRMED, confidence=0.9,
        ))
        state.add_finding(Finding(
            title="Weak credentials on 10.10.10.20 (ssh)", asset="10.10.10.20",
            severity=Severity.HIGH, status=FindingStatus.CONFIRMED, confidence=0.95,
        ))
        # A finding still in DETECTED is NOT retestable yet.
        state.add_finding(Finding(
            title="Missing HSTS", asset="10.10.10.20",
            severity=Severity.LOW, status=FindingStatus.DETECTED,
        ))
        return state

    def test_only_confirmed_or_reported_are_retestable(self):
        state = self._state_with_findings()
        retestable = get_retestable_findings(state)
        titles = {f.title for f in retestable}
        assert "Missing HSTS" not in titles  # DETECTED excluded
        assert len(retestable) == 2

    def test_remediated_finding_is_dismissed(self):
        state = self._state_with_findings()
        sqli = next(f for f in state.findings if "sql" in f.title.lower())
        msg = mark_retest_result(sqli, still_vulnerable=False, evidence="patched, 200 on quote")
        assert sqli.status == FindingStatus.DISMISSED
        assert sqli.confidence == 0.1
        assert any("[RETEST" in e and "Fixed" in e for e in sqli.evidence)
        assert "REMEDIATED" in msg

    def test_still_vulnerable_finding_retains_status_and_gains_evidence(self):
        state = self._state_with_findings()
        creds = next(f for f in state.findings if "credential" in f.title.lower())
        before = creds.status
        msg = mark_retest_result(creds, still_vulnerable=True, evidence="admin:admin still valid")
        assert creds.status == before  # unchanged
        assert any("[RETEST" in e and "Still vulnerable" in e for e in creds.evidence)
        assert "STILL VULNERABLE" in msg

    def test_retest_summary_counts_fixed_and_still_vulnerable(self):
        state = self._state_with_findings()
        sqli = next(f for f in state.findings if "sql" in f.title.lower())
        creds = next(f for f in state.findings if "credential" in f.title.lower())
        mark_retest_result(sqli, still_vulnerable=False, evidence="fixed")
        mark_retest_result(creds, still_vulnerable=True, evidence="still weak")

        summary = retest_summary(state)
        assert "Already retested: 2" in summary
        assert "Fixed: 1" in summary
        assert "Still vulnerable: 1" in summary


# =========================================================================== #
# 5. AD tool command construction + input validation (direct, _run mocked)
# =========================================================================== #

@pytest.mark.unit
class TestADCommandConstruction:
    """Exercise active_directory.py command-building directly by capturing the
    command string handed to the (mocked) subprocess layer. This verifies the
    impacket/ldap invocations are shaped correctly and that target validation
    blocks injection before any command is built."""

    def _capture(self, monkeypatch):
        from quarr.tools import active_directory as ad
        captured = {}
        monkeypatch.setattr(ad, "_run", lambda cmd, timeout=120: captured.setdefault("cmd", cmd) or "OK")
        return ad, captured

    def test_asrep_roast_builds_getnpusers(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        ad.kerberos_asrep_roast(target="10.10.10.10", domain="corp.local")
        assert "impacket-GetNPUsers" in cap["cmd"]
        assert "corp.local/" in cap["cmd"]
        assert "-dc-ip 10.10.10.10" in cap["cmd"]
        assert "-no-pass" in cap["cmd"] and "hashcat" in cap["cmd"]

    def test_kerberoast_builds_getuserspns_with_auth(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        ad.kerberos_kerberoast(target="10.10.10.10", domain="corp.local",
                               username="jsmith", password="P@ss")
        assert "impacket-GetUserSPNs" in cap["cmd"]
        assert "corp.local/jsmith" in cap["cmd"]
        assert "-request" in cap["cmd"]

    def test_secrets_dump_builds_secretsdump(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        ad.secrets_dump(target="10.10.10.10", username="Administrator",
                        password="P@ss", domain="corp.local")
        assert "impacket-secretsdump" in cap["cmd"]
        assert "@10.10.10.10" in cap["cmd"]

    def test_psexec_builds_command(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        ad.psexec(target="10.10.10.11", username="Administrator",
                  password="P@ss", command="ipconfig", domain="corp.local")
        assert "impacket-psexec" in cap["cmd"]
        assert "@10.10.10.11" in cap["cmd"]
        assert "ipconfig" in cap["cmd"]

    def test_ldap_search_autogenerates_base_dn(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        ad.ldap_search(target="dc01.corp.local")
        # base_dn auto-derived from the hostname components.
        assert "DC=dc01,DC=corp,DC=local" in cap["cmd"]
        assert "ldap://dc01.corp.local" in cap["cmd"]

    def test_rpc_enum_null_session_when_no_creds(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        ad.rpc_enum(target="10.10.10.10")
        assert "rpcclient" in cap["cmd"]
        assert "enumdomusers" in cap["cmd"]
        assert "-N" in cap["cmd"]  # null session

    def test_target_validation_blocks_injection(self, monkeypatch):
        ad, cap = self._capture(monkeypatch)
        # A metacharacter-laden target must raise before any command is built.
        with pytest.raises(ValueError):
            ad.secrets_dump(target="10.10.10.10; rm -rf /", username="a", password="b")
        assert "cmd" not in cap  # _run was never reached
