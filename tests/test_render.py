"""Tests for the CLI renderer (quarr/cli/render.py)."""

import pytest

from quarr.cli.render import PlainRenderer, get_renderer
from quarr.core.models import (
    Engagement,
    Finding,
    PentestState,
    Severity,
    ToolExecution,
)


def _state():
    st = PentestState()
    st.engagement = Engagement(name="R", allowed_targets=["10.0.0.1"], excluded_targets=["10.0.0.2"])
    st.add_finding(Finding(title="SQLi", asset="10.0.0.1", severity=Severity.CRITICAL))
    st.record_tool(ToolExecution(tool_name="nmap", arguments={"t": "x"}, result_summary="", success=True))
    st.record_tool(ToolExecution(tool_name="sqlmap", arguments={}, result_summary="", success=False))
    return st


@pytest.mark.unit
class TestPlainRenderer:
    def test_findings_table(self, capsys):
        PlainRenderer().findings_table(_state())
        out = capsys.readouterr().out
        assert "SQLi" in out and "CRITICAL" in out

    def test_findings_table_empty(self, capsys):
        PlainRenderer().findings_table(PentestState())
        assert "No findings" in capsys.readouterr().out

    def test_state_panel(self, capsys):
        PlainRenderer().state_panel(_state())
        assert "ENGAGEMENT" in capsys.readouterr().out

    def test_scope_panel_with_exclusions(self, capsys):
        PlainRenderer().scope_panel(_state().engagement)
        out = capsys.readouterr().out
        assert "10.0.0.1" in out and "Excluded" in out

    def test_history_table(self, capsys):
        PlainRenderer().history_table(_state())
        out = capsys.readouterr().out
        assert "nmap" in out and "OK" in out and "FAIL" in out

    def test_history_empty(self, capsys):
        PlainRenderer().history_table(PentestState())
        assert "No tool executions" in capsys.readouterr().out

    def test_sessions_table(self, capsys):
        PlainRenderer().sessions_table([{"id": "ENG-1", "name": "S", "findings": 2}])
        assert "ENG-1" in capsys.readouterr().out

    def test_sessions_empty(self, capsys):
        PlainRenderer().sessions_table([])
        assert "No saved sessions" in capsys.readouterr().out

    def test_result_and_info(self, capsys):
        r = PlainRenderer()
        r.result_panel("done")
        r.info("hello")
        out = capsys.readouterr().out
        assert "done" in out and "hello" in out


@pytest.mark.unit
def test_get_renderer_returns_a_renderer():
    r = get_renderer()
    # Must expose the renderer interface regardless of rich availability.
    for m in ("findings_table", "state_panel", "scope_panel", "history_table",
              "sessions_table", "result_panel", "info"):
        assert hasattr(r, m)
