"""Shared pytest fixtures for the QUARR test suite (Phase 3)."""

from pathlib import Path

import pytest

from quarr.core.models import (
    Engagement,
    Finding,
    FindingStatus,
    Host,
    Observation,
    PentestState,
    Service,
    Severity,
)
from quarr.tools.executor import ExecResult

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---- Domain fixtures ---------------------------------------------------------

@pytest.fixture
def sample_engagement():
    return Engagement(
        name="Test Engagement",
        allowed_targets=["10.10.10.0/24", "target.lab.local"],
        excluded_targets=["10.10.10.1"],
        allowed_operations=[],  # empty = allow all
    )


@pytest.fixture
def populated_state(sample_engagement):
    state = PentestState()
    state.engagement = sample_engagement
    state.add_host(Host(address="10.10.10.20", hostname="target.lab.local",
                        services=[
                            Service(host="10.10.10.20", port=22, name="ssh",
                                    product="OpenSSH", version="8.9"),
                            Service(host="10.10.10.20", port=80, name="http",
                                    product="Apache", version="2.4.52"),
                        ]))
    state.add_observation(Observation(source_tool="nmap",
                                      description="Discovered SSH and HTTP"))
    state.add_finding(Finding(
        title="SQL Injection", severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED, asset="10.10.10.20",
        description="Injectable id parameter", confidence=0.9,
    ))
    return state


# ---- Filesystem isolation ----------------------------------------------------

@pytest.fixture
def tmp_engagements_dir(monkeypatch, tmp_path):
    import quarr.core.persistence as persistence
    monkeypatch.setattr(persistence, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    return tmp_path / "engagements"


@pytest.fixture
def tmp_audit_path(tmp_path):
    return str(tmp_path / "audit.log")


# ---- Mock LLM ----------------------------------------------------------------

class MockLLM:
    """Scripted async LLM client matching BaseLLMClient.chat()."""
    def __init__(self, script=None):
        self._script = list(script or [])

    async def chat(self, messages, tools=None, max_tokens=1024):
        if self._script:
            return self._script.pop(0)
        return {"content": "done", "tool_calls": [], "raw": {}}


def make_tool_call(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}


def make_final(text):
    return {"content": text, "tool_calls": [], "raw": {}}


@pytest.fixture
def mock_llm():
    return MockLLM


# ---- Executor mock -----------------------------------------------------------

@pytest.fixture
def mock_executor():
    class FakeExec:
        def __init__(self, stdout="", exit_code=0):
            self.stdout = stdout
            self.exit_code = exit_code
            self.last_argv = None

        def run(self, argv, timeout, cwd=None, env=None):
            self.last_argv = argv
            return ExecResult(stdout=self.stdout, stderr="",
                              exit_code=self.exit_code, duration_ms=1)
    return FakeExec


# ---- Fixture loader ----------------------------------------------------------

@pytest.fixture
def load_fixture():
    def _load(name):
        return (FIXTURES_DIR / name).read_text()
    return _load
