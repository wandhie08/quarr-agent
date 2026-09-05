"""Unit tests for Phase 6 CLI (render, progress, interactive, argparse)."""

import sys

import pytest

from quarr.cli.interactive import run_interactive
from quarr.cli.progress import ProgressReporter
from quarr.cli.render import SEVERITY_STYLE, PlainRenderer, RichRenderer, get_renderer

# ---- render ----

@pytest.mark.unit
def test_get_renderer_rich_available():
    assert isinstance(get_renderer(), RichRenderer)


@pytest.mark.unit
def test_get_renderer_falls_back_to_plain(monkeypatch):
    # Simulate rich being unavailable.
    monkeypatch.setitem(sys.modules, "rich", None)
    r = get_renderer()
    assert isinstance(r, PlainRenderer)


@pytest.mark.unit
def test_severity_style_complete():
    for sev in ("critical", "high", "medium", "low", "info"):
        assert sev in SEVERITY_STYLE


@pytest.mark.unit
def test_rich_findings_table_renders(populated_state, capsys):
    r = RichRenderer()
    r.findings_table(populated_state)
    out = capsys.readouterr().out
    assert "SQL Injection" in out


@pytest.mark.unit
def test_plain_findings_table(populated_state, capsys):
    PlainRenderer().findings_table(populated_state)
    out = capsys.readouterr().out
    assert "SQL Injection" in out


# ---- progress ----

@pytest.mark.unit
async def test_progress_status_awaitable():
    pr = ProgressReporter()
    await pr.status("working...")  # should not raise


@pytest.mark.unit
def test_plan_progress_format():
    pr = ProgressReporter()
    assert pr.plan_progress(2, 5) == "Step 2/5"


@pytest.mark.unit
def test_spinner_context_manager():
    pr = ProgressReporter()
    with pr.spinner("scanning"):
        pass  # enters/exits cleanly


# ---- interactive ----

class _FakeAgent:
    def __init__(self):
        from quarr.core.models import Engagement, PentestState
        self.state = PentestState()
        self.state.engagement = Engagement(name="T", allowed_targets=["10.0.0.0/8"])
        self.calls = []

    async def run(self, query, status_callback=None):
        self.calls.append(query)
        return "done"


@pytest.mark.unit
async def test_interactive_invalid_then_back():
    agent = _FakeAgent()
    inputs = iter(["9", "5"])  # invalid choice, then back
    renderer = PlainRenderer()
    await run_interactive(agent, renderer, input_fn=lambda p="": next(inputs))
    # No agent runs triggered by invalid/back.
    assert agent.calls == []


@pytest.mark.unit
async def test_interactive_discovery_runs_agent():
    agent = _FakeAgent()
    inputs = iter(["1", "10.0.0.5", "5"])
    renderer = PlainRenderer()
    await run_interactive(agent, renderer, input_fn=lambda p="": next(inputs))
    assert any("10.0.0.5" in c for c in agent.calls)


# ---- argparse ----

@pytest.mark.unit
def test_argparse_flags():
    import main
    args = main.parse_args(["--interactive", "--scope", "10.0.0.1",
                            "--scope", "10.0.0.2", "--backend", "ollama"])
    assert args.interactive is True
    assert args.scope == ["10.0.0.1", "10.0.0.2"]
    assert args.backend == "ollama"


@pytest.mark.unit
def test_argparse_engagement_and_report():
    import main
    args = main.parse_args(["--engagement", "ENG-123", "--report", "technical"])
    assert args.engagement == "ENG-123"
    assert args.report == "technical"


@pytest.mark.unit
def test_argparse_invalid_backend_exits():
    import main
    with pytest.raises(SystemExit):
        main.parse_args(["--backend", "bogus"])
