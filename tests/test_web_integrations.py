"""Unit tests for web integrations (Phase 2, Req 6)."""

import pytest

from quarr.tools.integrations.sqlmap import SqlmapIntegration
from quarr.tools.integrations.dirsearch import DirsearchIntegration
from quarr.tools.integrations.whatweb import WhatWebIntegration
from quarr.tools.integrations.sslscan import SSLScanIntegration
from quarr.tools.executor import ExecResult


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
def test_sqlmap_non_interactive_and_capped():
    fake = FakeExec("sqlmap identified the following injection point")
    integ = SqlmapIntegration(executor=fake)
    result = integ.run(target="http://target/page?id=1", level=99, risk=99)
    assert "--batch" in fake.last_argv
    # Level/risk clamped to max 5/3.
    assert fake.last_argv[fake.last_argv.index("--level") + 1] == "5"
    assert fake.last_argv[fake.last_argv.index("--risk") + 1] == "3"
    assert result.parsed["injectable"] is True


@pytest.mark.unit
def test_sqlmap_url_scheme_added():
    fake = FakeExec("no injection")
    integ = SqlmapIntegration(executor=fake)
    integ.run(target="target/page?id=1")
    url = fake.last_argv[fake.last_argv.index("-u") + 1]
    assert url.startswith("https://")


@pytest.mark.unit
def test_dirsearch_parses_paths():
    out = "200   1KB   http://target/admin/\n404   0B   http://target/nope"
    fake = FakeExec(out)
    integ = DirsearchIntegration(executor=fake)
    result = integ.run(target="http://target")
    assert "-q" in fake.last_argv
    assert any(p["status"] == 200 for p in result.parsed["paths"])


@pytest.mark.unit
def test_whatweb_parses_technologies():
    out = '{"target":"http://target","plugins":{"Apache":{},"PHP":{}}}'
    fake = FakeExec(out)
    integ = WhatWebIntegration(executor=fake)
    result = integ.run(target="http://target")
    assert "Apache" in result.parsed["technologies"]
    assert "PHP" in result.parsed["technologies"]


@pytest.mark.unit
def test_sslscan_detects_weak_protocols():
    out = "SSLv3   enabled\nTLSv1.0   enabled\nTLSv1.2   enabled"
    fake = FakeExec(out)
    integ = SSLScanIntegration(executor=fake)
    result = integ.run(target="target.lab.local")
    assert "SSLv3" in result.parsed["weak_protocols"]
    assert "TLSv1.0" in result.parsed["weak_protocols"]
