"""End-to-end agent harness — real agent loop + real tools against a live lab.

This is the most realistic scenario short of using a paid LLM: the ACTUAL
QuarrAgent loop runs, the ACTUAL tool-registry handlers execute REAL nmap
against the lab target, results are parsed and recorded in agent state — only
the LLM is scripted (deterministic tool-calls) so the test is reproducible and
free.

    agent.run(query)
      └─ scripted LLM emits tool_call("network_discovery", target=...)
           └─ TOOL_REGISTRY handler -> NmapIntegration (REAL nmap subprocess)
                └─ parse real XML -> recorded in agent.state.tool_history

OPT-IN (same gating as test_live_tools.py):

    export QUARR_LIVE_TARGET="127.0.0.1"
    pytest tests/test_live_agent.py -m live -v

Skipped entirely unless QUARR_LIVE_TARGET is set, and skipped per-test if nmap
is not installed. Never runs in CI (default addopts = -m 'not live').
"""

import os
import shutil

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.models import Engagement

pytestmark = pytest.mark.live

LIVE_TARGET = os.environ.get("QUARR_LIVE_TARGET")

if not LIVE_TARGET:
    pytest.skip(
        "QUARR_LIVE_TARGET not set — skipping live agent harness.",
        allow_module_level=True,
    )


class ScriptedLLM:
    """Deterministic LLM: replays a fixed list of chat() responses in order."""

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


def make_agent(script, monkeypatch):
    # Loopback/private target must be allowed in scope for the lab.
    eng = Engagement(
        name="Live Lab",
        allowed_targets=[LIVE_TARGET, "127.0.0.0/8", "10.0.0.0/8"],
        allowed_operations=[],  # empty = allow all registered tools
    )
    # Do not construct a real LLM client (would need a backend).
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))
    agent = QuarrAgent(engagement=eng, backend="ollama")
    agent.client = ScriptedLLM(script)
    return agent


@pytest.mark.live
async def test_agent_runs_real_nmap_discovery(monkeypatch):
    """Agent loop drives REAL nmap discovery and records it in state."""
    if shutil.which("nmap") is None:
        pytest.skip("nmap not installed")

    agent = make_agent(
        [
            tool_call("network_discovery", target=LIVE_TARGET),
            final(f"Discovery complete for {LIVE_TARGET}."),
        ],
        monkeypatch,
    )

    result = await agent.run(f"Discover live hosts on {LIVE_TARGET}")

    # The agent produced a final answer.
    assert "complete" in result.lower()
    # The real tool execution was recorded.
    assert len(agent.state.tool_history) == 1
    exec_record = agent.state.tool_history[0]
    assert exec_record.tool_name == "network_discovery"
    # A real nmap run against a reachable lab host should succeed.
    assert exec_record.success


@pytest.mark.live
async def test_agent_service_enumeration_finds_port(monkeypatch):
    """Agent loop drives REAL nmap service scan; discovered services land in state."""
    if shutil.which("nmap") is None:
        pytest.skip("nmap not installed")

    agent = make_agent(
        [
            tool_call("service_enumeration", target=LIVE_TARGET, profile="basic"),
            final("Service enumeration complete."),
        ],
        monkeypatch,
    )

    result = await agent.run(f"Enumerate services on {LIVE_TARGET}")

    assert "complete" in result.lower()
    svc_exec = next(t for t in agent.state.tool_history if t.tool_name == "service_enumeration")
    assert svc_exec.success
    # Deep assertion: the real scan populated the world model with a host that
    # has at least one open service.
    assert len(agent.state.hosts) >= 1
    all_services = [s for h in agent.state.hosts for s in h.services]
    assert len(all_services) >= 1, "service enumeration should record at least one service"
    # An observation about the enumeration must also be recorded.
    assert any(o.source_tool == "service_enumeration" for o in agent.state.observations)


@pytest.mark.live
async def test_agent_multi_step_recon(monkeypatch):
    """Two real tool calls in one agent session, both recorded in order."""
    if shutil.which("nmap") is None:
        pytest.skip("nmap not installed")

    agent = make_agent(
        [
            tool_call("network_discovery", target=LIVE_TARGET),
            tool_call("service_enumeration", target=LIVE_TARGET, profile="basic"),
            final("Recon phase complete."),
        ],
        monkeypatch,
    )

    result = await agent.run(f"Do recon on {LIVE_TARGET}")

    assert "complete" in result.lower()
    names = [t.tool_name for t in agent.state.tool_history]
    assert names == ["network_discovery", "service_enumeration"]
