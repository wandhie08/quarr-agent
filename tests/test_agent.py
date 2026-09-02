"""Unit tests for agent loop hardening (Phase 1, Req 3)."""

import pytest

from quarr.core.agent import QuarrAgent
from quarr.core.models import Engagement
from quarr.core.exceptions import ToolError
import quarr.core.agent as agent_mod


class MockLLM:
    """Scripted async LLM client matching BaseLLMClient.chat()."""
    def __init__(self, script):
        self._script = list(script)

    async def chat(self, messages, tools=None, max_tokens=1024):
        if self._script:
            return self._script.pop(0)
        return {"content": "done", "tool_calls": [], "raw": {}}


def tool_call(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}


def final(text):
    return {"content": text, "tool_calls": [], "raw": {}}


@pytest.fixture
def engagement():
    return Engagement(
        name="Test",
        allowed_targets=["10.10.10.0/24"],
        allowed_operations=[],  # allow all
    )


def _make_agent(engagement, monkeypatch, script):
    # Avoid constructing a real LLM client (would need a backend).
    monkeypatch.setattr(agent_mod, "create_llm_client",
                        lambda **kw: MockLLM(script))
    agent = QuarrAgent(engagement=engagement, backend="ollama")
    agent.client = MockLLM(script)
    return agent


def _patch_handler(monkeypatch, tool_name, fn):
    """Patch only the handler of an existing ToolMeta, keeping its metadata."""
    meta = agent_mod.TOOL_REGISTRY[tool_name]
    monkeypatch.setattr(meta, "handler", fn)


@pytest.mark.unit
async def test_tool_exception_caught_loop_continues(engagement, monkeypatch):
    # First LLM turn calls a tool that raises; second turn returns a final answer.
    agent = _make_agent(engagement, monkeypatch, [
        tool_call("network_discovery", target="10.10.10.20"),
        final("Recovered and summarized."),
    ])

    def boom(**kwargs):
        raise ToolError("scanner crashed", context={"tool": "network_discovery"})

    _patch_handler(monkeypatch, "network_discovery", boom)

    result = await agent.run("scan the host")
    assert "Recovered" in result
    # The failed execution was recorded.
    assert any(not t.success for t in agent.state.tool_history)


@pytest.mark.unit
async def test_policy_violation_fed_back_without_terminating(monkeypatch):
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"],
                     allowed_operations=[])
    agent = _make_agent(eng, monkeypatch, [
        tool_call("network_discovery", target="192.168.1.1"),  # out of scope
        final("Adjusted to in-scope target."),
    ])
    # Handler should never be reached for the out-of-scope call.
    called = {"n": 0}

    def handler(**kwargs):
        called["n"] += 1
        return "ok"

    _patch_handler(monkeypatch, "network_discovery", handler)

    result = await agent.run("scan")
    assert "Adjusted" in result
    assert called["n"] == 0  # blocked by policy, not executed


@pytest.mark.unit
async def test_three_consecutive_tool_errors_terminate(engagement, monkeypatch):
    # LLM keeps calling failing tools with different args each turn.
    script = [
        tool_call("network_discovery", target="10.10.10.21"),
        tool_call("network_discovery", target="10.10.10.22"),
        tool_call("network_discovery", target="10.10.10.23"),
        tool_call("network_discovery", target="10.10.10.24"),
        final("should not reach here"),
    ]
    agent = _make_agent(engagement, monkeypatch, script)

    def boom(**kwargs):
        raise ToolError("always fails")

    _patch_handler(monkeypatch, "network_discovery", boom)

    result = await agent.run("scan repeatedly")
    assert "halted" in result.lower()
