"""End-to-end tests: Web API + real QuarrAgent (mock LLM client).

These exercise the real agent loop (policy, state, audit, approval gate) driven
through the REST /query endpoint and the Live Console WebSocket, using a mocked
LLM client so no LLM server is required.
"""

import pytest
from fastapi.testclient import TestClient

import quarr.core.agent as agent_mod
from quarr.api import security as sec
from quarr.api.app import app, set_agent_factory
from quarr.api.auth import UserStore as _UserStore
from quarr.api.live import set_live_agent_factory
from quarr.api.wiring import wire_agents
from quarr.core import persistence
from quarr.core.agent import QuarrAgent
from quarr.core.config import Settings


class MockLLM:
    """Scripted LLM: emits one tool call then a final answer."""
    def __init__(self, script):
        self._script = list(script)

    async def chat(self, messages, tools=None, max_tokens=1024):
        if self._script:
            return self._script.pop(0)
        return {"content": "done", "tool_calls": [], "raw": {}}


def _tool_call(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}


def _final(text):
    return {"content": text, "tool_calls": [], "raw": {}}


@pytest.fixture
def client(tmp_path, monkeypatch, populated_state):
    monkeypatch.setattr(persistence, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    store = _UserStore()
    store.add("admin", "adminpw", role="admin")
    store.add("op", "oppw", role="operator")
    sec.init_security(Settings(_env_file=None, jwt_secret="x" * 40), store)
    # allow-all operations so network_discovery passes scope
    populated_state.engagement.allowed_operations = []
    persistence.save_state(populated_state)
    return TestClient(app), populated_state.engagement.id


def _token(c, u, p):
    return c.post("/api/auth/login", json={"username": u, "password": p}).json()["access_token"]


@pytest.mark.integration
def test_rest_query_with_real_agent(client, monkeypatch):
    c, eng_id = client
    # Real QuarrAgent, but mock the LLM client it builds.
    script = [_tool_call("network_discovery", target="10.10.10.20"), _final("Recon complete.")]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: MockLLM(script))
    # Patch the tool handler so no real nmap runs.
    meta = agent_mod.TOOL_REGISTRY["network_discovery"]
    monkeypatch.setattr(meta, "handler", lambda **kw: "Nmap scan report for 10.10.10.20\nHost is up")

    set_agent_factory(lambda eng: QuarrAgent(engagement=eng, backend="ollama"))
    try:
        tok = _token(c, "op", "oppw")
        r = c.post(f"/api/engagements/{eng_id}/query", json={"query": "discover hosts"},
                   headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert "recon complete" in r.json()["result"].lower()
    finally:
        set_agent_factory(None)


@pytest.mark.integration
def test_live_console_real_agent_streaming(client, monkeypatch):
    c, eng_id = client
    script = [_tool_call("network_discovery", target="10.10.10.20"), _final("Live recon done.")]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: MockLLM(script))
    meta = agent_mod.TOOL_REGISTRY["network_discovery"]
    monkeypatch.setattr(meta, "handler", lambda **kw: "Nmap scan report for 10.10.10.20")

    def live_factory(eng, approval):
        return QuarrAgent(engagement=eng, backend="ollama",
                          approval_gate=approval.gate_async, session_role=approval.role)

    set_live_agent_factory(live_factory)
    try:
        tok = _token(c, "op", "oppw")
        with c.websocket_connect(f"/ws/live?token={tok}&engagement={eng_id}") as ws:
            assert ws.receive_json()["type"] == "connected"
            ws.send_json({"type": "run", "query": "discover"})
            # network_discovery is MEDIUM risk → no approval prompt; expect status then result.
            msgs = []
            for _ in range(6):
                m = ws.receive_json()
                msgs.append(m)
                if m["type"] == "result":
                    break
            kinds = [m["type"] for m in msgs]
            assert "result" in kinds
            result = [m for m in msgs if m["type"] == "result"][0]
            assert "live recon done" in result["data"].lower()
    finally:
        set_live_agent_factory(None)


@pytest.mark.integration
def test_live_console_real_agent_dangerous_tool_denied(client, monkeypatch):
    c, eng_id = client
    # Agent tries a CRITICAL tool (hash_crack) → approval prompt → deny.
    script = [_tool_call("hash_crack", hash="abc", wordlist="/usr/share/wordlists/x"),
              _final("stopped after denial")]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: MockLLM(script))
    meta = agent_mod.TOOL_REGISTRY.get("hash_crack")
    if meta is None:
        pytest.skip("hash_crack tool not registered")
    monkeypatch.setattr(meta, "handler", lambda **kw: "cracked!")
    # Force CRITICAL risk to guarantee an approval prompt.
    from quarr.core.models import RiskLevel
    monkeypatch.setattr(meta, "risk", RiskLevel.CRITICAL)

    def live_factory(eng, approval):
        return QuarrAgent(engagement=eng, backend="ollama",
                          approval_gate=approval.gate_async, session_role=approval.role)

    set_live_agent_factory(live_factory)
    try:
        tok = _token(c, "admin", "adminpw")
        with c.websocket_connect(f"/ws/live?token={tok}&engagement={eng_id}") as ws:
            assert ws.receive_json()["type"] == "connected"
            ws.send_json({"type": "run", "query": "crack the hash"})
            # Expect an approval_request; deny it.
            req = None
            for _ in range(6):
                m = ws.receive_json()
                if m["type"] == "approval_request":
                    req = m
                    break
            assert req is not None and req["tool"] == "hash_crack"
            ws.send_json({"type": "approval_response", "approved": False})
            # Agent should recover and produce a final result (denial fed back).
            result = None
            for _ in range(6):
                m = ws.receive_json()
                if m["type"] == "result":
                    result = m
                    break
            assert result is not None
    finally:
        set_live_agent_factory(None)


@pytest.mark.integration
def test_wire_agents_installs_factories(monkeypatch):
    # wire_agents should set both factories to callables.
    from quarr.api import app as app_mod
    from quarr.api import live as live_mod

    set_agent_factory(None)
    set_live_agent_factory(None)
    wire_agents(Settings(_env_file=None))
    assert app_mod.get_agent_factory() is not None
    assert live_mod.get_live_agent_factory() is not None
    # cleanup
    set_agent_factory(None)
    set_live_agent_factory(None)
