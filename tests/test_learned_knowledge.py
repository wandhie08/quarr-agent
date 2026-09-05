"""Tests for the cross-engagement learning layer (quarr/knowledge/learned.py).

Covers the persistence primitives (record, persist, retrieve, dedup, corrupt-
store safety) and — most importantly — a 2-engagement proof that the agent
becomes MORE TARGETED after learning: knowledge confirmed in engagement A is
injected into engagement B's LLM context.

The store is redirected to a temp dir via QUARR_LEARN_DIR so tests never touch
the real ~/.quarr store.
"""

import importlib

import pytest

import quarr.core.agent as agent_mod
from quarr.core.agent import QuarrAgent
from quarr.core.models import (
    Engagement,
    Finding,
    FindingStatus,
    Host,
    PentestState,
    Service,
    Severity,
    ToolExecution,
)


@pytest.fixture
def learned(tmp_path, monkeypatch):
    """Fresh, isolated learned-knowledge store per test."""
    monkeypatch.setenv("QUARR_LEARN_DIR", str(tmp_path / "learn"))
    import quarr.knowledge.learned as mod
    importlib.reload(mod)  # pick up the patched QUARR_LEARN_DIR
    mod.reset_store()
    yield mod
    mod.reset_store()


# =========================================================================== #
# Persistence primitives
# =========================================================================== #

@pytest.mark.unit
class TestLearnedStore:
    def test_record_and_retrieve_finding(self, learned):
        learned.record_finding("Werkzeug", "excessive-data-exposure",
                               "api_data_exposure_check", "password leak")
        hints = learned.get_hints(technologies=["Werkzeug/2.2.3"])
        assert "excessive-data-exposure" in hints
        assert "api_data_exposure_check" in hints

    def test_dedup_bumps_count(self, learned):
        for _ in range(3):
            learned.record_finding("Apache", "sql-injection", "sqli_scan")
        store = learned.load_store()
        pats = [p for p in store["finding_patterns"] if p["technology"] == "Apache"]
        assert len(pats) == 1                # deduplicated
        assert pats[0]["count"] == 3         # count bumped

    def test_persists_across_reload(self, learned):
        learned.record_finding("nginx", "path-traversal", "nuclei")
        # Simulate a new process by reloading the module (store is on disk).
        importlib.reload(learned)
        assert "path-traversal" in learned.get_hints(technologies=["nginx"])

    def test_tool_effectiveness_best_tool(self, learned):
        learned.record_tool_result("Werkzeug", "api_data_exposure_check", True)
        learned.record_tool_result("Werkzeug", "api_data_exposure_check", True)
        learned.record_tool_result("Werkzeug", "web_crawl", False)
        learned.record_finding("Werkzeug", "bola", "api_bola_check")
        hints = learned.get_hints(technologies=["Werkzeug"])
        assert "Most effective tool on Werkzeug: api_data_exposure_check" in hints

    def test_no_hints_when_nothing_learned(self, learned):
        assert learned.get_hints(technologies=["Werkzeug"]) == ""

    def test_irrelevant_technology_returns_nothing(self, learned):
        learned.record_finding("Werkzeug", "bola", "api_bola_check")
        # A totally unrelated tech should not surface Werkzeug hints.
        assert learned.get_hints(technologies=["IIS"]) == ""

    def test_corrupt_store_is_safe(self, learned):
        # Write garbage to the store file; load must not raise.
        p = learned._store_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{ this is not valid json ]")
        assert learned.load_store()["finding_patterns"] == []
        learned.record_finding("Apache", "xss", "xss_scan")  # still works
        assert "xss" in learned.get_hints(technologies=["Apache"])

    def test_empty_inputs_ignored(self, learned):
        learned.record_finding("", "bola", "t")       # no technology
        learned.record_finding("Apache", "", "t")     # no vuln type
        assert learned.load_store()["finding_patterns"] == []


# =========================================================================== #
# Learn from a full engagement state
# =========================================================================== #

@pytest.mark.unit
class TestRecordFromState:
    def _state_with_confirmed(self):
        st = PentestState()
        st.engagement = Engagement(name="A", allowed_targets=["10.0.0.5"])
        st.add_host(Host(address="10.0.0.5", services=[
            Service(host="10.0.0.5", port=5000, name="http", product="Werkzeug"),
        ]))
        st.add_finding(Finding(
            title="Excessive Data Exposure on /_debug", asset="10.0.0.5",
            severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
        ))
        st.record_tool(ToolExecution(tool_name="api_data_exposure_check",
                                     arguments={}, result_summary="", success=True))
        return st

    def test_records_confirmed_findings_only(self, learned):
        st = self._state_with_confirmed()
        # Add a non-confirmed finding that must NOT be learned.
        st.add_finding(Finding(title="Maybe XSS", asset="10.0.0.5",
                               status=FindingStatus.DETECTED))
        n = learned.record_from_state(st)
        assert n >= 1
        pats = learned.load_store()["finding_patterns"]
        vts = {p["vuln_type"] for p in pats}
        assert "excessive-data-exposure" in vts
        assert "maybe" not in vts and "xss" not in vts  # DETECTED not recorded

    def test_maps_finding_to_asset_technology(self, learned):
        learned.record_from_state(self._state_with_confirmed())
        hints = learned.get_hints(technologies=["Werkzeug"])
        assert "excessive-data-exposure" in hints


# =========================================================================== #
# 2-ENGAGEMENT PROOF: the agent gets smarter
# =========================================================================== #

class _ScriptedLLM:
    def __init__(self, script):
        self._s = list(script)

    async def chat(self, messages, tools=None, max_tokens=1024):
        # Capture the injected context so the proof can inspect it.
        _ScriptedLLM.last_context = "\n".join(
            m["content"] for m in messages if m["role"] == "system"
        )
        return self._s.pop(0) if self._s else {"content": "done", "tool_calls": [], "raw": {}}


def _tc(name, **args):
    return {"content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}], "raw": {}}


def _final(t):
    return {"content": t, "tool_calls": [], "raw": {}}


@pytest.mark.integration
async def test_agent_learns_across_two_engagements(learned, monkeypatch):
    """Engagement A confirms an API3 leak on a Werkzeug target; Engagement B
    (a DIFFERENT Werkzeug target) must receive that learned hint in its LLM
    context — proving cross-engagement learning."""

    reg = agent_mod.TOOL_REGISTRY
    # Real handlers patched to canned output.
    monkeypatch.setattr(reg["web_fingerprint"], "handler",
                        lambda **kw: "Summary : Werkzeug/2.2.3 Python/3.11")
    monkeypatch.setattr(reg["api_data_exposure_check"], "handler",
                        lambda **kw: "🚨 API3 — Sensitive field(s) exposed: password")

    # ---- Engagement A: discover Werkzeug, confirm data exposure ----
    eng_a = Engagement(name="Lab A", allowed_targets=["10.0.0.5"], allowed_operations=[])
    script_a = [
        _tc("web_fingerprint", target="http://10.0.0.5:5000"),
        _final("Confirmed: Werkzeug API leaks password via /_debug (Excessive Data Exposure)."),
    ]
    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: _ScriptedLLM(script_a))
    agent_a = QuarrAgent(engagement=eng_a, backend="ollama", session_role="operator")
    agent_a.client = _ScriptedLLM(script_a)
    # Seed a CONFIRMED finding tied to the Werkzeug host so learning records it.
    agent_a.state.add_host(Host(address="10.0.0.5", services=[
        Service(host="10.0.0.5", port=5000, name="http", product="Werkzeug")]))
    agent_a.state.add_finding(Finding(
        title="Excessive Data Exposure on /_debug", asset="10.0.0.5",
        severity=Severity.HIGH, status=FindingStatus.CONFIRMED))
    await agent_a.run("Assess the API at http://10.0.0.5:5000")

    # The learning store now holds the Werkzeug pattern.
    assert "excessive-data-exposure" in learned.get_hints(technologies=["Werkzeug"])

    # ---- Engagement B: a NEW Werkzeug target, fresh agent ----
    eng_b = Engagement(name="Lab B", allowed_targets=["10.0.0.9"], allowed_operations=[])
    script_b = [_final("starting")]
    agent_b = QuarrAgent(engagement=eng_b, backend="ollama", session_role="operator")
    agent_b.client = _ScriptedLLM(script_b)
    # Give B a Werkzeug host so the learned hint is relevant.
    agent_b.state.add_host(Host(address="10.0.0.9", services=[
        Service(host="10.0.0.9", port=5000, name="http", product="Werkzeug")]))
    agent_b.state.current_objective = "Assess the API at http://10.0.0.9:5000"

    # Build context for engagement B and assert the learned hint is injected.
    ctx = agent_b._build_context()
    ctx_text = "\n".join(m["content"] for m in ctx)
    assert "LEARNED KNOWLEDGE (from previous engagements)" in ctx_text
    assert "excessive-data-exposure" in ctx_text
    assert "Werkzeug" in ctx_text
    # Engagement B is now primed with A's knowledge → the agent is "smarter".
