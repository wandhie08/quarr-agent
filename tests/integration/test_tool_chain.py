"""Integration test: tool integration run() path with mocked executor + real parser."""

import pytest

from quarr.tools.integrations.nmap import NmapIntegration
from quarr.tools.checker import ToolChecker


@pytest.fixture(autouse=True)
def force_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    ToolChecker.clear_cache()
    yield
    ToolChecker.clear_cache()


@pytest.mark.integration
def test_nmap_run_parses_fixture(mock_executor, load_fixture):
    fake = mock_executor(stdout=load_fixture("nmap.xml"))
    integ = NmapIntegration(mode="service", executor=fake)
    result = integ.run(target="10.10.10.20", ports="22,80")
    assert result.success
    assert len(result.parsed["hosts"]) == 1
    assert {s["port"] for s in result.parsed["hosts"][0]["services"]} == {22, 80}
