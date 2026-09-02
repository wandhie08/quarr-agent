"""Unit tests for credential integrations (Phase 2, Req 7)."""

from pathlib import Path

import pytest

from quarr.tools.integrations.hydra import HydraIntegration
from quarr.tools.integrations.hashcat import HashcatIntegration
from quarr.tools.integrations.john import JohnIntegration
from quarr.tools.integrations import _validate
from quarr.tools.executor import ExecResult
from quarr.core.exceptions import ArgumentValidationError
from quarr.core.models import RiskLevel

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


@pytest.fixture
def allow_tmp(monkeypatch, tmp_path):
    # Allow only tmp_path; create a wordlist inside it.
    wl = tmp_path / "rockyou.txt"
    wl.write_text("password\n123456\n")
    orig = _validate.validate_file_path
    monkeypatch.setattr(
        _validate, "validate_file_path",
        lambda p, allowed_dirs=(str(tmp_path),): orig(p, allowed_dirs),
    )
    return str(wl), str(tmp_path)


@pytest.mark.unit
def test_credential_tools_are_high_or_critical_risk():
    assert HydraIntegration.risk_level == RiskLevel.HIGH
    assert HashcatIntegration.risk_level == RiskLevel.CRITICAL
    assert JohnIntegration.risk_level == RiskLevel.CRITICAL


@pytest.mark.unit
def test_hydra_redacts_cracked_password():
    fake = FakeExec((FIXTURES / "hydra_output.txt").read_text())
    integ = HydraIntegration(executor=fake)
    result = integ.run(target="10.10.10.20", service="ssh")
    assert result.parsed["credentials_found"] == 1
    # The cracked password must not appear in the summary.
    assert "SuperSecret123" not in result.parsed["summary"]
    assert "***REDACTED***" in result.parsed["summary"]


@pytest.mark.unit
def test_wordlist_path_outside_allowlist_rejected():
    integ = HydraIntegration(executor=FakeExec(""))
    with pytest.raises(ArgumentValidationError):
        integ.run(target="10.10.10.20", service="ssh",
                  passlist="/etc/shadow")


@pytest.mark.unit
def test_hashcat_path_allowlisted(allow_tmp):
    wl, base = allow_tmp
    hf = Path(base) / "hashes.txt"
    hf.write_text("deadbeef\n")
    fake = FakeExec("Status.........: Cracked")
    integ = HashcatIntegration(executor=fake)
    result = integ.run(hashfile=str(hf), wordlist=wl, mode="0")
    assert fake.last_argv[0] == "hashcat"
    assert "--quiet" in fake.last_argv
    assert result.parsed["status"] == "Cracked"


@pytest.mark.unit
def test_john_traversal_rejected():
    integ = JohnIntegration(executor=FakeExec(""))
    with pytest.raises(ArgumentValidationError):
        integ.run(hashfile="../../etc/passwd", wordlist="/usr/share/wordlists/x")
