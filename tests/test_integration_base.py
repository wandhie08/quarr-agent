"""Unit tests for the ToolIntegration base class (Phase 2, Req 1)."""

import pytest

from quarr.tools.integrations.base import ToolIntegration, ToolResult
from quarr.tools.executor import ExecResult
from quarr.core.exceptions import ToolNotFoundError, ToolOutputParseError
from quarr.core.models import RiskLevel
from quarr.tools.checker import ToolChecker


class DummyIntegration(ToolIntegration):
    binary_name = "echo"
    name = "dummy"
    category = "test"
    risk_level = RiskLevel.LOW
    default_timeout = 5

    def build_command(self, **kwargs):
        return ["echo", kwargs.get("value", "x")]

    def parse_output(self, raw):
        if raw.strip() == "FAIL":
            raise ToolOutputParseError("bad output", context={"raw": raw})
        return {"echoed": raw.strip()}


@pytest.fixture(autouse=True)
def clear_cache():
    ToolChecker.clear_cache()
    yield
    ToolChecker.clear_cache()


@pytest.mark.unit
def test_run_end_to_end(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/bin/echo")

    class FakeExec:
        def run(self, argv, timeout, cwd=None, env=None):
            return ExecResult(stdout="hello", stderr="", exit_code=0, duration_ms=3)

    integ = DummyIntegration(executor=FakeExec())
    result = integ.run(value="hello")
    assert isinstance(result, ToolResult)
    assert result.success is True
    assert result.parsed == {"echoed": "hello"}
    assert result.duration_ms == 3


@pytest.mark.unit
def test_unavailable_binary_raises(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    integ = DummyIntegration()
    with pytest.raises(ToolNotFoundError):
        integ.run(value="x")


@pytest.mark.unit
def test_parse_error_returns_failed_result(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: "/bin/echo")

    class FakeExec:
        def run(self, argv, timeout, cwd=None, env=None):
            return ExecResult(stdout="FAIL", stderr="", exit_code=0, duration_ms=1)

    integ = DummyIntegration(executor=FakeExec())
    result = integ.run()
    assert result.success is False
    assert result.error is not None
    assert result.parsed == {}


@pytest.mark.unit
def test_build_command_shape():
    integ = DummyIntegration()
    assert integ.build_command(value="target") == ["echo", "target"]
