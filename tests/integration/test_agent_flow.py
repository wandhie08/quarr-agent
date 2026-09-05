"""Integration test: full agent turn with mock LLM + mock tool updates state."""

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.models import Engagement
from tests.conftest import MockLLM, make_final, make_tool_call


@pytest.mark.integration
async def test_agent_tool_call_updates_state(monkeypatch):
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"],
                     allowed_operations=[])
    script = [
        make_tool_call("network_discovery", target="10.10.10.20"),
        make_final("Host discovered and summarized."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: MockLLM(script))
    agent = QuarrAgent(engagement=eng, backend="ollama")
    agent.client = MockLLM(script)

    # Patch the nmap handler to return a canned nmap-style summary string.
    meta = agent_mod.TOOL_REGISTRY["network_discovery"]
    monkeypatch.setattr(meta, "handler",
                        lambda **kw: "Nmap scan report for 10.10.10.20\nHost is up")

    result = await agent.run("discover hosts")
    assert "summarized" in result.lower()
    # The tool execution was recorded in state.
    assert len(agent.state.tool_history) == 1
    assert agent.state.tool_history[0].tool_name == "network_discovery"
