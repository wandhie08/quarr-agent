"""End-to-end reporting test: agent run -> populated state -> reports.

Unlike test_live_*.py these run in the default suite (no live target, no real
tools, no paid LLM). They verify the *reporting pipeline* end-to-end:

    scripted LLM + mock tool
        -> QuarrAgent records execution/host in state
        -> we add a confirmed finding (as a triage step would)
        -> executive / technical / JSON reports are generated
        -> the finding, asset and remediation actually appear in the output

This closes the loop from "agent did something" to "the report a human/manager
receives reflects it".
"""

import json

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.models import Engagement, Finding, FindingStatus, Severity
from quarr.core.reporter import (
    export_json,
    export_markdown,
    generate_executive_summary,
    generate_technical_report,
)
from tests.conftest import MockLLM, make_final, make_tool_call


def _run_agent_and_populate(monkeypatch):
    """Drive one agent turn (mock tool) and return the agent with a finding added."""
    eng = Engagement(
        name="Reporting E2E",
        allowed_targets=["10.10.10.0/24"],
        allowed_operations=[],
    )
    script = [
        make_tool_call("network_discovery", target="10.10.10.20"),
        make_final("Discovery done."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: MockLLM(script))
    agent = QuarrAgent(engagement=eng, backend="ollama")
    agent.client = MockLLM(script)

    meta = agent_mod.TOOL_REGISTRY["network_discovery"]
    monkeypatch.setattr(
        meta, "handler",
        lambda **kw: "Nmap scan report for 10.10.10.20\nHost is up",
    )
    return agent


@pytest.mark.integration
async def test_agent_run_to_reports_contains_finding(monkeypatch):
    agent = _run_agent_and_populate(monkeypatch)
    result = await agent.run("discover hosts")
    assert "done" in result.lower()
    assert len(agent.state.tool_history) == 1

    # A triage/validation step produces a confirmed finding.
    agent.state.add_finding(
        Finding(
            title="SQL Injection",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            asset="10.10.10.20",
            description="The id parameter is injectable.",
            confidence=0.9,
            remediation="Use parameterized queries.",
        )
    )

    # --- Executive summary ---
    exec_sum = generate_executive_summary(agent.state)
    assert "EXECUTIVE SUMMARY" in exec_sum
    assert "Reporting E2E" in exec_sum          # engagement name
    assert "HIGH" in exec_sum                    # overall risk rating from the finding
    assert "SQL Injection" in exec_sum           # the finding surfaces
    assert "parameterized queries" in exec_sum   # remediation surfaces

    # --- Technical report ---
    tech = generate_technical_report(agent.state)
    assert "TECHNICAL SECURITY ASSESSMENT REPORT" in tech
    assert "SQL Injection" in tech
    assert "10.10.10.20" in tech                 # asset in the findings section
    assert "network_discovery" in tech           # tool execution log reflects the run
    assert "CONFIRMED" in tech                    # finding status


@pytest.mark.integration
async def test_agent_run_to_json_export_roundtrips(monkeypatch, tmp_path):
    agent = _run_agent_and_populate(monkeypatch)
    await agent.run("discover hosts")
    agent.state.add_finding(
        Finding(
            title="Cross-Site Scripting",
            severity=Severity.MEDIUM,
            status=FindingStatus.CONFIRMED,
            asset="10.10.10.20",
            confidence=0.8,
        )
    )

    path = tmp_path / "findings.json"
    export_json(agent.state, str(path))
    data = json.loads(path.read_text())

    assert data["engagement"]["name"] == "Reporting E2E"
    assert data["summary"]["findings"] == 1
    assert data["summary"]["risk_rating"] == "MEDIUM"
    assert data["summary"]["tool_executions"] == 1
    titles = [f["title"] for f in data["findings"]]
    assert "Cross-Site Scripting" in titles


@pytest.mark.integration
async def test_markdown_export_writes_file(monkeypatch, tmp_path):
    agent = _run_agent_and_populate(monkeypatch)
    await agent.run("discover hosts")
    agent.state.add_finding(
        Finding(title="Open Redirect", severity=Severity.LOW,
                status=FindingStatus.CONFIRMED, asset="10.10.10.20")
    )

    exec_path = tmp_path / "exec.md"
    tech_path = tmp_path / "tech.md"
    export_markdown(agent.state, str(exec_path), "executive")
    export_markdown(agent.state, str(tech_path), "technical")

    assert exec_path.read_text().startswith("# EXECUTIVE SUMMARY")
    tech_text = tech_path.read_text()
    assert "Open Redirect" in tech_text
    assert "TECHNICAL SECURITY ASSESSMENT REPORT" in tech_text


@pytest.mark.integration
def test_empty_state_reports_are_safe():
    """Reports must render sensibly even with no findings/hosts."""
    from quarr.core.models import PentestState

    state = PentestState()
    state.engagement = Engagement(name="Empty", allowed_targets=["10.0.0.1"])

    exec_sum = generate_executive_summary(state)
    tech = generate_technical_report(state)
    assert "INFORMATIONAL" in exec_sum  # no findings -> informational risk
    assert "No security findings" in exec_sum
    assert "No hosts discovered" in tech
