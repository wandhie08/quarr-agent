"""Tests for methodology playbooks (quarr/knowledge/methodology.py).

Verifies phase/domain lookups return the right attributed playbook, that every
returned block cites its source (THP3 / Operator Handbook), and that the agent
injects a phase-appropriate playbook into its LLM context.
"""

import pytest

from quarr.knowledge.methodology import (
    METHODOLOGY_PLAYBOOKS,
    get_methodology,
    list_playbooks,
)


@pytest.mark.unit
class TestMethodologyLookup:
    def test_ad_exploit_returns_ad_chain(self):
        out = get_methodology(phase="exploit", domains=["Windows AD", "kerberos"])
        assert "Active Directory Attack Chain" in out
        assert "kerberoasting" in out.lower()
        assert "DCSync" in out

    def test_web_vuln_scan_returns_web_exploitation(self):
        out = get_methodology(phase="vuln_scan", domains=["Apache", "http"],
                              query="find sql injection")
        assert "Web Exploitation" in out
        assert "sql injection" in out.lower()

    def test_recon_returns_recon_playbook(self):
        out = get_methodology(phase="recon", domains=[])
        assert "External Recon" in out
        assert "nmap" in out

    def test_domain_keyword_in_query_matches(self):
        out = get_methodology(phase=None, domains=[], query="perform privilege escalation")
        assert "Privilege Escalation" in out

    def test_no_match_returns_empty(self):
        assert get_methodology(phase="", domains=["nonexistent-tech"], query="") == ""

    def test_api_playbook_from_hacking_apis(self):
        out = get_methodology(phase="vuln_scan", domains=["api"], query="test for bola and jwt")
        assert "API Security Testing" in out
        assert "bola" in out.lower() and "mass assignment" in out.lower()
        assert "Hacking APIs" in out

    def test_mobile_playbook_from_mastg(self):
        out = get_methodology(phase="vuln_scan", domains=["android", "apk"],
                              query="mobile app insecure storage")
        assert "MASVS" in out
        assert "MASTG" in out  # OWASP attribution present

    def test_web_bughunting_playbook(self):
        out = get_methodology(phase="vuln_scan", domains=["bugbounty"], query="hunt for idor and ssrf")
        assert "Web Bug Hunting" in out or "API Security" in out

    def test_malware_analysis_playbook(self):
        out = get_methodology(phase=None, domains=["dfir", "malware"], query="analyze a malware sample")
        assert "Malware Analysis" in out
        assert "yara" in out.lower()
        assert "Malware Analyst's Cookbook" in out

    def test_network_forensics_playbook(self):
        out = get_methodology(phase=None, domains=["network_forensics"], query="pcap beaconing c2")
        assert "Network Forensics" in out
        assert "Davidoff" in out or "wireshark" in out.lower()

    def test_disk_memory_forensics_playbook(self):
        out = get_methodology(phase=None, domains=["incident_response", "memory"], query="acquire and analyze memory")
        assert "Forensics" in out
        assert "volatility" in out.lower()

    def test_max_results_bounds_output(self):
        out = get_methodology(phase="exploit", domains=["ad", "network", "privesc"], max_results=1)
        # Only one playbook header line (▸) should appear.
        assert out.count("▸") == 1


@pytest.mark.unit
class TestAttribution:
    def test_every_returned_block_cites_a_source(self):
        for phase in ("recon", "discovery", "vuln_scan", "exploit"):
            out = get_methodology(phase=phase, domains=[])
            if out:
                assert "Source:" in out
                assert ("THP3" in out) or ("Operator Handbook" in out)

    def test_all_playbooks_have_sources_and_tools(self):
        assert len(METHODOLOGY_PLAYBOOKS) >= 6
        for pb in METHODOLOGY_PLAYBOOKS:
            assert pb["sources"], f"{pb['name']} missing sources"
            assert pb["tools"], f"{pb['name']} missing tools"
            assert pb["techniques"], f"{pb['name']} missing techniques"
            assert pb["phase"] in ("recon", "discovery", "vuln_scan", "exploit")

    def test_list_playbooks_nonempty(self):
        names = list_playbooks()
        assert "Active Directory Attack Chain" in names
        assert len(names) == len(METHODOLOGY_PLAYBOOKS)


# =========================================================================== #
# Agent injects methodology into context
# =========================================================================== #

@pytest.mark.integration
def test_agent_context_includes_methodology():
    from quarr.core.agent import QuarrAgent
    from quarr.core.models import Engagement, Host, Service

    eng = Engagement(name="m", allowed_targets=["10.0.0.5"], allowed_operations=[])
    agent = QuarrAgent(model="x", engagement=eng, backend="ollama", session_role="operator")
    # A Windows AD host + an exploit-phase objective should surface the AD chain.
    agent.state.add_host(Host(address="10.0.0.5", services=[
        Service(host="10.0.0.5", port=445, name="smb", product="Windows AD")]))
    agent.state.current_objective = "dump domain controller hashes via kerberos"

    ctx = "\n".join(m["content"] for m in agent._build_context())
    assert "METHODOLOGY PLAYBOOK (reference)" in ctx
    assert "Source:" in ctx
