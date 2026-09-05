"""
Quick smoke test for QUARR Agent.
Run: python -m pytest tests/ -v
Or:  python tests/test_quarr.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def test_tools_registry():
    from quarr.tools.registry import TOOL_REGISTRY
    assert len(TOOL_REGISTRY) >= 90, f"Expected 90+ tools, got {len(TOOL_REGISTRY)}"
    print(f"✅ {len(TOOL_REGISTRY)} tools registered")


def test_models():
    from quarr.core.models import (
        Engagement,
        Finding,
        FindingStatus,
        Host,
        PentestState,
        Service,
        Severity,
    )
    state = PentestState()
    eng = Engagement(name="Test", allowed_targets=["10.10.10.0/24"])
    state.engagement = eng
    state.add_host(Host(address="10.10.10.20", services=[
        Service(host="10.10.10.20", port=22, name="ssh")
    ]))
    state.add_finding(Finding(
        title="Test", severity=Severity.HIGH,
        status=FindingStatus.DETECTED, asset="10.10.10.20"
    ))
    assert len(state.hosts) == 1
    assert len(state.findings) == 1
    print("✅ Models OK")


def test_policy():
    from quarr.core.models import Engagement
    from quarr.core.policy import PolicyEngine, PolicyViolation
    eng = Engagement(
        name="Test",
        allowed_targets=["10.10.10.0/24", "target.com"],
        excluded_targets=["10.10.10.1"],
        allowed_operations=[],  # empty = allow all
    )
    policy = PolicyEngine()

    # In scope
    assert policy.authorize("service_enumeration", {"target": "10.10.10.20"}, eng)
    assert policy.authorize("sqli_scan", {"target": "https://target.com/page?id=1"}, eng)

    # Out of scope
    try:
        policy.authorize("service_enumeration", {"target": "192.168.1.1"}, eng)
        raise AssertionError("Should have raised")
    except PolicyViolation:
        pass

    # Excluded
    try:
        policy.authorize("service_enumeration", {"target": "10.10.10.1"}, eng)
        raise AssertionError("Should have raised")
    except PolicyViolation:
        pass

    print("✅ Policy OK")


def test_validator():
    from quarr.core.models import Finding, FindingStatus, Severity
    from quarr.core.validator import FindingValidator
    f = Finding(
        title="SQL Injection", severity=Severity.CRITICAL,
        status=FindingStatus.OBSERVATION, asset="target.com"
    )
    assert FindingValidator.transition(f, FindingStatus.HYPOTHESIS, "test")
    assert f.status == FindingStatus.HYPOTHESIS
    assert not FindingValidator.transition(f, FindingStatus.CONFIRMED, "skip")  # Can't skip
    print("✅ Validator OK")


def test_knowledge():
    from quarr.knowledge.base import get_cwe_for_finding, retrieve_knowledge
    k = retrieve_knowledge(phase="exploit", query="sql injection")
    assert len(k) > 0
    cwe = get_cwe_for_finding("SQL Injection")
    assert cwe["id"] == "CWE-89"
    print("✅ Knowledge OK")


def test_parsers():
    from quarr.parsers.network import parse_tool_output
    nmap_out = """Nmap scan report for 10.10.10.20
22/tcp open ssh OpenSSH 8.9
80/tcp open http Apache 2.4"""
    parsed = parse_tool_output("service_enumeration", nmap_out)
    assert len(parsed["services"]) == 2
    print("✅ Parsers OK")


def test_agent_creation():
    from quarr.core.agent import QuarrAgent
    from quarr.core.models import Engagement
    eng = Engagement(name="Test", allowed_targets=["10.10.10.0/24"])
    agent = QuarrAgent(engagement=eng, backend="ollama")
    assert agent.client is not None
    assert len(agent.state.engagement.allowed_targets) == 1
    print("✅ QuarrAgent OK")


def test_reporter():
    from quarr.core.models import Engagement, PentestState
    from quarr.core.reporter import generate_executive_summary, generate_technical_report
    state = PentestState()
    state.engagement = Engagement(name="Test", allowed_targets=["target.com"])
    exec_sum = generate_executive_summary(state)
    tech_rep = generate_technical_report(state)
    assert "EXECUTIVE" in exec_sum
    assert "TECHNICAL" in tech_rep
    print("✅ Reporter OK")


if __name__ == "__main__":
    test_tools_registry()
    test_models()
    test_policy()
    test_validator()
    test_knowledge()
    test_parsers()
    test_agent_creation()
    test_reporter()
    print("\n✅ ALL TESTS PASSED")
