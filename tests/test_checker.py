"""Unit tests for the tool availability checker (Phase 2, Req 3)."""

import pytest

from quarr.tools.checker import ToolChecker


@pytest.fixture(autouse=True)
def clear_cache():
    ToolChecker.clear_cache()
    yield
    ToolChecker.clear_cache()


@pytest.mark.unit
def test_available_true(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    assert ToolChecker.is_available("nmap") is True


@pytest.mark.unit
def test_available_false(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: None)
    assert ToolChecker.is_available("nmap") is False


@pytest.mark.unit
def test_result_is_cached(monkeypatch):
    calls = {"n": 0}

    def fake_which(b):
        calls["n"] += 1
        return "/usr/bin/nmap"

    monkeypatch.setattr("shutil.which", fake_which)
    ToolChecker.is_available("nmap")
    ToolChecker.is_available("nmap")
    assert calls["n"] == 1  # second call served from cache


@pytest.mark.unit
def test_check_all(monkeypatch):
    present = {"nmap", "nikto"}
    monkeypatch.setattr("shutil.which",
                        lambda b: "/usr/bin/x" if b in present else None)
    result = ToolChecker.check_all(["nmap", "nikto", "sqlmap"])
    assert result == {"nmap": True, "nikto": True, "sqlmap": False}


@pytest.mark.unit
def test_report_format(monkeypatch):
    monkeypatch.setattr("shutil.which",
                        lambda b: "/usr/bin/x" if b == "nmap" else None)
    report = ToolChecker.report(["nmap", "sqlmap"])
    assert "nmap" in report and "sqlmap" in report
    assert "✓" in report and "✗" in report
