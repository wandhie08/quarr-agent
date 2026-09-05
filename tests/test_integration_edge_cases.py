"""Edge-case unit tests for the modern tool integrations (Opsi A).

These complement the happy-path tests in test_network_integrations.py,
test_web_integrations.py and test_credential_integrations.py by exercising the
messy real-world outputs a tool can produce:

    * empty stdout (tool ran but found nothing / was killed early)
    * malformed output (truncated XML/JSON, garbage lines)
    * mixed valid + garbage lines
    * output that legitimately means "no findings"

The contract we verify is defined by ToolIntegration.run() in
quarr/tools/integrations/base.py:

    - When parse_output() raises ToolOutputParseError, run() must NOT propagate;
      it returns ToolResult(success=False, parsed={}, error=<msg>).
    - When parsing succeeds (even with zero findings), run() returns
      success=True with a structured parsed dict.

No real binaries are executed — a FakeExec returns scripted stdout/exit codes.
"""

import pytest

from quarr.core.exceptions import TargetValidationError, ToolOutputParseError
from quarr.tools.executor import ExecResult
from quarr.tools.integrations._validate import validate_target
from quarr.tools.integrations.dirsearch import DirsearchIntegration
from quarr.tools.integrations.hashcat import HashcatIntegration
from quarr.tools.integrations.hydra import HydraIntegration
from quarr.tools.integrations.john import JohnIntegration
from quarr.tools.integrations.masscan import MasscanIntegration
from quarr.tools.integrations.nikto import NiktoIntegration
from quarr.tools.integrations.nmap import NmapIntegration
from quarr.tools.integrations.nuclei import NucleiIntegration
from quarr.tools.integrations.sqlmap import SqlmapIntegration
from quarr.tools.integrations.sslscan import SSLScanIntegration
from quarr.tools.integrations.whatweb import WhatWebIntegration

# Parsers are also exercised directly to assert the exact exception type.
from quarr.tools.parsers.nikto import parse_nikto
from quarr.tools.parsers.nmap import parse_nmap_xml
from quarr.tools.parsers.nuclei import parse_nuclei_jsonl


class FakeExec:
    """Scripted executor: returns a fixed stdout/exit_code without running anything."""

    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.exit_code = exit_code
        self.last_argv = None

    def run(self, argv, timeout, cwd=None, env=None):
        self.last_argv = argv
        return ExecResult(
            stdout=self.stdout, stderr="", exit_code=self.exit_code, duration_ms=3
        )


@pytest.fixture(autouse=True)
def force_available(monkeypatch):
    """Pretend every binary is installed so run() reaches build/parse."""
    monkeypatch.setattr("shutil.which", lambda b: f"/usr/bin/{b}")
    from quarr.tools.checker import ToolChecker

    ToolChecker.clear_cache()
    yield
    ToolChecker.clear_cache()


# ---------------------------------------------------------------------------
# Parser-level: exact exception behavior on empty / malformed input
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestParserExceptions:
    @pytest.mark.parametrize("bad", ["", "   ", "\n\t "])
    def test_nmap_empty_raises(self, bad):
        with pytest.raises(ToolOutputParseError):
            parse_nmap_xml(bad)

    def test_nmap_malformed_xml_raises(self):
        with pytest.raises(ToolOutputParseError):
            parse_nmap_xml("<nmaprun><host><addr")  # truncated

    @pytest.mark.parametrize("bad", ["", "   "])
    def test_nikto_empty_raises(self, bad):
        with pytest.raises(ToolOutputParseError):
            parse_nikto(bad)

    def test_nikto_malformed_json_raises(self):
        with pytest.raises(ToolOutputParseError):
            parse_nikto('{"vulnerabilities": [')  # truncated JSON

    def test_nuclei_none_raises(self):
        with pytest.raises(ToolOutputParseError):
            parse_nuclei_jsonl(None)

    def test_nuclei_empty_is_valid_empty(self):
        # Nuclei printing nothing = no findings, NOT an error.
        assert parse_nuclei_jsonl("") == {"findings": []}
        assert parse_nuclei_jsonl("\n\n") == {"findings": []}

    def test_nuclei_only_garbage_raises(self):
        with pytest.raises(ToolOutputParseError):
            parse_nuclei_jsonl("not json\nalso not json\n")

    def test_nuclei_mixed_skips_garbage(self):
        raw = 'garbage line\n{"template-id":"x","info":{"name":"X","severity":"low"}}\n'
        out = parse_nuclei_jsonl(raw)
        assert len(out["findings"]) == 1
        assert out["findings"][0]["template_id"] == "x"


@pytest.mark.unit
class TestTargetValidation:
    """Regression tests for validate_target — found via the live harness (Opsi C).

    A live nikto/sslscan run against host:port (e.g. 127.0.0.1:8080) previously
    raised TargetValidationError because ':' was not allowlisted. host:port must
    be accepted, while genuine shell metacharacters must still be rejected.
    """

    @pytest.mark.parametrize(
        "target",
        ["127.0.0.1:8080", "target.lab.local:443", "10.10.10.20", "10.10.10.0/24"],
    )
    def test_accepts_host_and_optional_port(self, target):
        # http(s):// prefix is stripped; trailing slash removed.
        assert validate_target(target) == target

    def test_strips_scheme_and_trailing_slash(self):
        assert validate_target("http://127.0.0.1:8080/") == "127.0.0.1:8080"

    @pytest.mark.parametrize(
        "bad",
        ["10.0.0.1; rm -rf /", "a b c", "$(reboot)", "host|nc evil", "x`id`"],
    )
    def test_still_rejects_shell_metacharacters(self, bad):
        with pytest.raises(TargetValidationError):
            validate_target(bad)


# ---------------------------------------------------------------------------
# Integration-level: run() converts parse failure into success=False
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestNmapEdgeCases:
    def test_empty_output_yields_failure_result(self):
        integ = NmapIntegration(executor=FakeExec(""))
        result = integ.run(target="10.10.10.20")
        assert result.success is False
        assert result.parsed == {}
        assert result.error and "nmap" in result.error.lower()

    def test_malformed_xml_yields_failure_result(self):
        integ = NmapIntegration(executor=FakeExec("<nmaprun><host"))
        result = integ.run(target="10.10.10.20")
        assert result.success is False
        assert result.error

    def test_valid_but_no_open_ports(self):
        # Well-formed XML, host down / no open ports -> success with empty lists.
        xml = '<nmaprun><host><address addr="10.10.10.20"/>' \
              '<status state="down"/></host></nmaprun>'
        integ = NmapIntegration(executor=FakeExec(xml))
        result = integ.run(target="10.10.10.20")
        assert result.success is True
        assert result.parsed["hosts"][0]["services"] == []
        assert result.parsed["services"] == []

    def test_closed_ports_are_filtered_out(self):
        xml = (
            '<nmaprun><host><address addr="10.10.10.20"/>'
            '<ports><port protocol="tcp" portid="22">'
            '<state state="closed"/></port></ports></host></nmaprun>'
        )
        integ = NmapIntegration(executor=FakeExec(xml))
        result = integ.run(target="10.10.10.20")
        assert result.success is True
        assert result.parsed["services"] == []


@pytest.mark.unit
class TestNiktoEdgeCases:
    def test_empty_output_yields_failure_result(self):
        integ = NiktoIntegration(executor=FakeExec(""))
        result = integ.run(target="10.10.10.20")
        assert result.success is False
        assert result.error

    def test_malformed_json_yields_failure_result(self):
        integ = NiktoIntegration(executor=FakeExec("{not valid json"))
        result = integ.run(target="10.10.10.20")
        assert result.success is False

    def test_dict_without_vulns_is_empty_success(self):
        integ = NiktoIntegration(executor=FakeExec('{"host": "10.10.10.20"}'))
        result = integ.run(target="10.10.10.20")
        assert result.success is True
        assert result.parsed["findings"] == []
        assert result.parsed["host"] == "10.10.10.20"

    def test_empty_json_array_is_empty_success(self):
        integ = NiktoIntegration(executor=FakeExec("[]"))
        result = integ.run(target="10.10.10.20")
        assert result.success is True
        assert result.parsed["findings"] == []


@pytest.mark.unit
class TestNucleiEdgeCases:
    def test_empty_output_is_success_no_findings(self):
        integ = NucleiIntegration(executor=FakeExec(""))
        result = integ.run(target="http://target.lab.local")
        assert result.success is True
        assert result.parsed["findings"] == []

    def test_only_garbage_yields_failure_result(self):
        integ = NucleiIntegration(executor=FakeExec("garbage\nmore garbage\n"))
        result = integ.run(target="http://target.lab.local")
        assert result.success is False
        assert result.error

    def test_mixed_valid_and_garbage(self):
        raw = 'oops\n{"template-id":"cve-2021","info":{"name":"RCE","severity":"critical"}}\n'
        integ = NucleiIntegration(executor=FakeExec(raw))
        result = integ.run(target="http://target.lab.local")
        assert result.success is True
        assert len(result.parsed["findings"]) == 1
        assert result.parsed["findings"][0]["severity"] == "critical"


@pytest.mark.unit
class TestMasscanEdgeCases:
    def test_empty_output_is_success_no_services(self):
        integ = MasscanIntegration(executor=FakeExec(""))
        result = integ.run(target="10.10.10.20", ports="1-1000")
        assert result.success is True
        assert result.parsed["services"] == []

    def test_malformed_json_yields_failure_result(self):
        integ = MasscanIntegration(executor=FakeExec("{ip: broken"))
        result = integ.run(target="10.10.10.20", ports="1-1000")
        assert result.success is False
        assert result.error

    def test_trailing_comma_is_tolerated(self):
        raw = '{"ip":"10.10.10.20","ports":[{"port":80,"proto":"tcp","status":"open"}]},'
        integ = MasscanIntegration(executor=FakeExec(raw))
        result = integ.run(target="10.10.10.20", ports="1-1000")
        assert result.success is True
        assert result.parsed["services"][0]["port"] == 80

    def test_already_bracketed_array(self):
        raw = '[{"ip":"10.10.10.21","ports":[{"port":443,"proto":"tcp","status":"open"}]}]'
        integ = MasscanIntegration(executor=FakeExec(raw))
        result = integ.run(target="10.10.10.21", ports="1-1000")
        assert result.success is True
        assert result.parsed["services"][0]["port"] == 443


@pytest.mark.unit
class TestSqlmapEdgeCases:
    def test_no_injection_output(self):
        integ = SqlmapIntegration(executor=FakeExec("all tested parameters do not appear"))
        result = integ.run(target="http://target/page?id=1")
        assert result.success is True
        assert result.parsed["injectable"] is False
        assert result.parsed["findings"] == []

    def test_empty_output_is_not_injectable(self):
        integ = SqlmapIntegration(executor=FakeExec(""))
        result = integ.run(target="http://target/page?id=1")
        assert result.success is True
        assert result.parsed["injectable"] is False

    def test_case_insensitive_detection(self):
        integ = SqlmapIntegration(executor=FakeExec("Parameter id IS VULNERABLE"))
        result = integ.run(target="http://target/page?id=1")
        assert result.parsed["injectable"] is True


@pytest.mark.unit
class TestDirsearchEdgeCases:
    def test_empty_output_no_paths(self):
        integ = DirsearchIntegration(executor=FakeExec(""))
        result = integ.run(target="http://target")
        assert result.success is True
        assert result.parsed["paths"] == []

    def test_only_error_statuses_are_dropped(self):
        out = "404   0B   http://target/nope\n500   0B   http://target/boom"
        integ = DirsearchIntegration(executor=FakeExec(out))
        result = integ.run(target="http://target")
        assert result.parsed["paths"] == []

    def test_redirect_statuses_are_kept(self):
        out = "301   0B   http://target/old"
        integ = DirsearchIntegration(executor=FakeExec(out))
        result = integ.run(target="http://target")
        assert result.parsed["paths"][0]["status"] == 301


@pytest.mark.unit
class TestWhatWebEdgeCases:
    def test_noise_lines_are_skipped(self):
        out = "WARNING: something\nnot json at all\n"
        integ = WhatWebIntegration(executor=FakeExec(out))
        result = integ.run(target="http://target")
        assert result.success is True
        assert result.parsed["technologies"] == []

    def test_empty_output(self):
        integ = WhatWebIntegration(executor=FakeExec(""))
        result = integ.run(target="http://target")
        assert result.success is True
        assert result.parsed["technologies"] == []

    def test_duplicate_technologies_deduped_and_sorted(self):
        out = (
            '{"target":"http://t","plugins":{"PHP":{},"Apache":{}}}\n'
            '{"target":"http://t","plugins":{"Apache":{},"jQuery":{}}}\n'
        )
        integ = WhatWebIntegration(executor=FakeExec(out))
        result = integ.run(target="http://target")
        assert result.parsed["technologies"] == ["Apache", "PHP", "jQuery"]


@pytest.mark.unit
class TestSSLScanEdgeCases:
    def test_empty_output_no_weak_protocols(self):
        integ = SSLScanIntegration(executor=FakeExec(""))
        result = integ.run(target="target.lab.local")
        assert result.success is True
        assert result.parsed["weak_protocols"] == []

    def test_all_modern_protocols_no_weak(self):
        out = "TLSv1.2   enabled\nTLSv1.3   enabled\nSSLv3   disabled\nTLSv1.0   disabled"
        integ = SSLScanIntegration(executor=FakeExec(out))
        result = integ.run(target="target.lab.local")
        assert result.parsed["weak_protocols"] == []
        assert result.parsed["protocols"]["TLSv1.3"] == "enabled"


@pytest.mark.unit
class TestCredentialEdgeCases:
    def test_hydra_empty_output_zero_creds(self):
        integ = HydraIntegration(executor=FakeExec(""))
        result = integ.run(target="10.10.10.20", service="ssh")
        assert result.success is True
        assert result.parsed["credentials_found"] == 0

    def test_hydra_no_secret_leak_on_failed_run(self):
        # Even noisy output must never surface a raw password.
        out = "login: admin   password: hunter2\n[ERROR] connection refused"
        integ = HydraIntegration(executor=FakeExec(out))
        result = integ.run(target="10.10.10.20", service="ssh")
        assert "hunter2" not in result.parsed["summary"]

    def test_hashcat_empty_output_running_status(self):
        integ = HashcatIntegration(executor=FakeExec(""))
        # build_command needs file paths; is_available is mocked, executor is fake,
        # but validate_file_path would reject nonexistent paths — so assert on parser
        # directly for the empty case.
        parsed = integ.parse_output("")
        assert parsed["cracked_count"] == 0
        assert parsed["status"] == "Running"

    def test_hashcat_summary_never_leaks(self):
        parsed = HashcatIntegration(executor=FakeExec("")).parse_output(
            "deadbeef:secretpass\nStatus.........: Cracked"
        )
        assert "secretpass" not in parsed["summary"]
        assert parsed["status"] == "Cracked"

    def test_john_empty_output_zero_cracked(self):
        parsed = JohnIntegration(executor=FakeExec("")).parse_output("")
        assert parsed["cracked_count"] == 0

    def test_john_parses_cracked_count(self):
        parsed = JohnIntegration(executor=FakeExec("")).parse_output(
            "2 password hashes cracked, 0 left"
        )
        assert parsed["cracked_count"] == 2
