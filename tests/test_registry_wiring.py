"""Tests for registry integration wiring (Phase 2, Req 8)."""

import pytest

from quarr.tools.registry import TOOL_REGISTRY, network_discovery, _delegate
from quarr.tools.integrations.nmap import NmapIntegration
from quarr.tools.checker import ToolChecker


@pytest.fixture(autouse=True)
def clear_cache():
    ToolChecker.clear_cache()
    yield
    ToolChecker.clear_cache()


@pytest.mark.unit
def test_registry_still_has_90_plus_tools():
    assert len(TOOL_REGISTRY) >= 90


@pytest.mark.unit
def test_migrated_names_present():
    for name in ("network_discovery", "service_enumeration", "web_vuln_scan",
                 "ssl_scan", "sqli_scan"):
        assert name in TOOL_REGISTRY


@pytest.mark.unit
def test_unavailable_tool_returns_friendly_string(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)  # nothing installed
    result = network_discovery("10.10.10.20")
    assert "[TOOL NOT INSTALLED]" in result
    assert "nmap" in result


@pytest.mark.unit
def test_delegate_summarizes_success(monkeypatch):
    from quarr.tools.executor import ExecResult
    monkeypatch.setattr("shutil.which", lambda b: "/usr/bin/nmap")

    class FakeExec:
        def run(self, argv, timeout, cwd=None, env=None):
            return ExecResult(
                stdout='<?xml version="1.0"?><nmaprun><host>'
                       '<status state="up"/><address addr="10.10.10.20"/>'
                       '<ports></ports></host></nmaprun>',
                stderr="", exit_code=0, duration_ms=2)

    out = _delegate(NmapIntegration(mode="discovery", executor=FakeExec()),
                    target="10.10.10.20")
    assert "nmap" in out
    assert "OK" in out
