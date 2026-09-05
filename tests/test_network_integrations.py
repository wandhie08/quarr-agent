"""Unit tests for network integrations (Phase 2, Req 5)."""

from pathlib import Path

import pytest

from quarr.core.exceptions import TargetValidationError
from quarr.tools.executor import ExecResult
from quarr.tools.integrations.masscan import MasscanIntegration
from quarr.tools.integrations.nikto import NiktoIntegration
from quarr.tools.integrations.nmap import NmapIntegration
from quarr.tools.integrations.nuclei import NucleiIntegration

FIXTURES = Path(__file__).parent / "fixtures"


class FakeExec:
    def __init__(self, stdout):
        self.stdout = stdout
        self.last_argv = None

    def run(self, argv, timeout, cwd=None, env=None):
        self.last_argv = argv
        return ExecResult(stdout=self.stdout, stderr="", exit_code=0, duration_ms=5)


@pytest.fixture(autouse=True)
def force_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    from quarr.tools.checker import ToolChecker
    ToolChecker.clear_cache()
    yield
    ToolChecker.clear_cache()


@pytest.mark.unit
def test_nmap_build_command_and_parse():
    fake = FakeExec((FIXTURES / "nmap.xml").read_text())
    integ = NmapIntegration(mode="service", executor=fake)
    result = integ.run(target="10.10.10.20", ports="22,80")
    assert fake.last_argv[:2] == ["nmap", "-sV"]
    assert "-oX" in fake.last_argv and "-" in fake.last_argv
    assert result.success
    assert len(result.parsed["hosts"]) == 1


@pytest.mark.unit
def test_nmap_discovery_mode():
    fake = FakeExec("<nmaprun></nmaprun>")
    integ = NmapIntegration(mode="discovery", executor=fake)
    integ.run(target="10.10.10.0/24")
    assert "-sn" in fake.last_argv


@pytest.mark.unit
def test_nmap_rejects_bad_target():
    integ = NmapIntegration(executor=FakeExec(""))
    with pytest.raises(TargetValidationError):
        integ.run(target="10.0.0.1; rm -rf /")


@pytest.mark.unit
def test_nikto_build_and_parse():
    fake = FakeExec((FIXTURES / "nikto.json").read_text())
    integ = NiktoIntegration(executor=fake)
    result = integ.run(target="10.10.10.20")
    assert "-Format" in fake.last_argv and "json" in fake.last_argv
    assert len(result.parsed["findings"]) == 2


@pytest.mark.unit
def test_nuclei_build_and_parse():
    fake = FakeExec((FIXTURES / "nuclei.jsonl").read_text())
    integ = NucleiIntegration(executor=fake)
    result = integ.run(target="target.lab.local")
    assert fake.last_argv[0] == "nuclei"
    assert "-jsonl" in fake.last_argv
    assert len(result.parsed["findings"]) == 2


@pytest.mark.unit
def test_masscan_build_and_parse():
    masscan_json = '{"ip":"10.10.10.20","ports":[{"port":22,"proto":"tcp","status":"open"}]},'
    fake = FakeExec(masscan_json)
    integ = MasscanIntegration(executor=fake)
    result = integ.run(target="10.10.10.20", ports="1-1000")
    assert fake.last_argv[0] == "masscan"
    assert "-oJ" in fake.last_argv
    assert result.parsed["services"][0]["port"] == 22
