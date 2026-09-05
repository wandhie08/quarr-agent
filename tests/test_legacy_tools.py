"""Unit tests for the legacy tool modules (Opsi B).

These nine modules (active_directory, secops, forensic, blue_team, mobile,
dfir, vuln_assess, threat_intel, threat_hunting) were previously excluded from
coverage in pyproject.toml. They are thin wrappers that:

    * validate their inputs,
    * build a shell command string, and
    * hand it to a module-level `_run` / `_shell` / `_run_cmd` / `_http_get`
      helper that calls subprocess.

We never execute a real command. Instead each test monkeypatches the module's
helper with a capturing stub, so we can assert:

    1. the correct binary + arguments are built,
    2. untrusted values are shell-quoted (command-injection safety),
    3. input validation rejects dangerous targets/paths,
    4. pure logic (playbooks, API-key gating, allow-lists) behaves correctly.

This is white-box unit testing of the command-construction layer — the layer
most likely to contain injection bugs — without needing the tools installed.
"""

import pytest

from quarr.tools import (
    active_directory as ad,
)
from quarr.tools import (
    blue_team as bt,
)
from quarr.tools import (
    dfir,
    forensic,
    mobile,
    secops,
)
from quarr.tools import (
    threat_hunting as th,
)
from quarr.tools import (
    threat_intel as ti,
)
from quarr.tools import (
    vuln_assess as va,
)


class Capture:
    """Records the command string passed to a patched runner and returns canned output."""

    def __init__(self, ret="[No output]"):
        self.calls = []
        self.ret = ret

    def __call__(self, cmd, timeout=None, *args, **kwargs):
        self.calls.append(cmd)
        return self.ret

    @property
    def last(self):
        return self.calls[-1] if self.calls else ""

    @property
    def all(self):
        return "\n".join(self.calls)


# ===========================================================================
# active_directory.py
# ===========================================================================


@pytest.mark.unit
class TestActiveDirectory:
    def test_validate_target_rejects_injection(self):
        with pytest.raises(ValueError):
            ad._validate_target("10.0.0.1; rm -rf /")
        with pytest.raises(ValueError):
            ad._validate_target("$(reboot)")

    def test_validate_target_accepts_hostname(self):
        assert ad._validate_target("dc01.corp.local") == "dc01.corp.local"

    def test_asrep_roast_builds_impacket_command(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(ad, "_run", cap)
        ad.kerberos_asrep_roast(target="10.10.10.5", domain="corp.local")
        assert "impacket-GetNPUsers" in cap.last
        assert "corp.local" in cap.last
        assert "-no-pass" in cap.last

    def test_secrets_dump_quotes_credentials(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(ad, "_run", cap)
        # A password containing shell metacharacters must be quoted, not expanded.
        ad.secrets_dump(target="10.10.10.5", username="admin", password="p@ss;rm -rf /")
        assert "impacket-secretsdump" in cap.last
        assert "rm -rf" not in cap.last.split("'p@ss")[0]  # dangerous part is inside quotes
        assert "'p@ss;rm -rf /'" in cap.last

    def test_bad_target_never_reaches_runner(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(ad, "_run", cap)
        with pytest.raises(ValueError):
            ad.psexec(target="a b; evil", username="u", password="p")
        assert cap.calls == []  # runner must not have been called


# ===========================================================================
# blue_team.py
# ===========================================================================


@pytest.mark.unit
class TestBlueTeam:
    def test_firewall_block_rejects_bad_ip(self):
        assert bt.firewall_block("not-an-ip").startswith("[ERROR]")
        assert bt.firewall_block("1.2.3.4; rm -rf /").startswith("[ERROR]")

    def test_firewall_block_valid_ip_builds_iptables(self, monkeypatch):
        cap = Capture(ret="ok")
        monkeypatch.setattr(bt, "_run", cap)
        out = bt.firewall_block("10.0.0.9")
        assert "iptables -A INPUT" in cap.last
        assert "10.0.0.9" in cap.last
        assert "DROP" in cap.last
        assert "Blocked" in out

    def test_log_analysis_unknown_type(self):
        assert bt.log_analysis(log_type="bogus").startswith("[ERROR]")

    def test_log_analysis_caps_lines_and_quotes_filter(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(bt, "_shell", cap)
        bt.log_analysis(log_type="auth", lines=99999, filter_pattern="Failed;evil")
        assert "tail -n 500" in cap.last  # capped at 500
        assert "'Failed;evil'" in cap.last  # filter is quoted

    def test_file_integrity_rejects_traversal(self):
        assert bt.file_integrity_check(directory="../../etc").startswith("[ERROR]")


# ===========================================================================
# forensic.py
# ===========================================================================


@pytest.mark.unit
class TestForensic:
    def test_validate_path_rejects_empty(self):
        with pytest.raises(ValueError):
            forensic._validate_path("   ")

    def test_memory_analysis_rejects_unknown_command(self):
        out = forensic.memory_analysis(dump_path="/tmp/mem.raw", command="evil")
        assert out.startswith("[ERROR]")

    def test_memory_analysis_maps_plugin(self, monkeypatch):
        cap = Capture(ret="output")
        monkeypatch.setattr(forensic, "_run", cap)
        forensic.memory_analysis(dump_path="/tmp/mem.raw", command="pslist")
        assert "windows.pslist.PsList" in cap.last
        assert "/tmp/mem.raw" in cap.last

    def test_metadata_extract_quotes_path(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(forensic, "_run", cap)
        forensic.metadata_extract("/tmp/eviltmp/file name.jpg")
        assert "exiftool" in cap.last
        assert "'/tmp/eviltmp/file name.jpg'" in cap.last

    def test_string_extract_clamps_min_length(self, monkeypatch):
        cap = Capture(ret="a\nb\nc")
        monkeypatch.setattr(forensic, "_run", cap)
        forensic.string_extract("/tmp/bin", min_length=999)
        assert "strings -n 20" in cap.last  # clamped to max 20


# ===========================================================================
# secops.py  (pure logic — no subprocess)
# ===========================================================================


@pytest.mark.unit
class TestSecops:
    def test_list_playbooks_contains_known(self):
        out = secops.list_playbooks()
        assert "brute_force_response" in out
        assert "malware_response" in out

    def test_get_playbook_known(self):
        out = secops.get_playbook("brute_force_response")
        assert "Brute Force Response" in out
        assert "Steps:" in out

    def test_get_playbook_unknown(self):
        assert secops.get_playbook("does_not_exist").startswith("[ERROR]")

    def test_compliance_report_unknown_framework(self):
        assert secops.compliance_report("bogus").startswith("[ERROR]")


# ===========================================================================
# mobile.py
# ===========================================================================


@pytest.mark.unit
class TestMobile:
    def test_validate_path_blocks_sensitive_dirs(self):
        with pytest.raises(ValueError):
            mobile._validate_path("/etc/passwd")
        with pytest.raises(ValueError):
            mobile._validate_path("/root/.ssh/id_rsa")
        with pytest.raises(ValueError):
            mobile._validate_path("../../secret")

    def test_validate_path_accepts_tmp(self):
        assert mobile._validate_path("/tmp/app.apk") == "/tmp/app.apk"

    def test_apk_decompile_rejects_bad_path(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(mobile, "_run_cmd", cap)
        with pytest.raises(ValueError):
            mobile.apk_decompile(apk_path="/etc/shadow")
        assert cap.calls == []

    def test_apk_secrets_scan_quotes_directory(self, monkeypatch):
        cap = Capture(ret="[No output]")
        monkeypatch.setattr(mobile, "_run_shell", cap)
        mobile.apk_secrets_scan(directory="/tmp/apk out")
        assert "'/tmp/apk out'" in cap.all


# ===========================================================================
# dfir.py
# ===========================================================================


@pytest.mark.unit
class TestDFIR:
    def test_incident_triage_runs_and_summarizes(self, monkeypatch):
        # incident_triage() flags a finding whenever the "modified binaries" or
        # "temp executables" checks return non-empty output, so a clean system
        # must return "[No output]" for those to yield the healthy summary.
        def fake_shell(cmd, timeout=None):
            if "-mtime -7" in cmd or "-executable" in cmd:
                return "[No output]"
            return "clean output"
        monkeypatch.setattr(dfir, "_shell", fake_shell)
        out = dfir.incident_triage()
        assert "TRIAGE SUMMARY" in out
        assert "No obvious indicators" in out

    def test_incident_triage_flags_suspicious_port(self, monkeypatch):
        def fake_shell(cmd, timeout=None):
            if "ss -tunapl state established" in cmd:
                return "ESTAB 0 0 10.0.0.1:4444 1.2.3.4:5555"
            return "clean"
        monkeypatch.setattr(dfir, "_shell", fake_shell)
        out = dfir.incident_triage()
        assert "Suspicious connection" in out
        assert "CRITICAL" in out


# ===========================================================================
# vuln_assess.py
# ===========================================================================


@pytest.mark.unit
class TestVulnAssess:
    def test_config_audit_ssh_builds_command(self, monkeypatch):
        cap = Capture(ret="PermitRootLogin no")
        monkeypatch.setattr(va, "_shell", cap)
        monkeypatch.setattr(va, "_run", cap)
        out = va.config_audit("ssh")
        # Should have inspected the sshd config in some command.
        assert any("ssh" in c for c in cap.calls)
        assert isinstance(out, str)

    def test_hardening_check_returns_report(self, monkeypatch):
        monkeypatch.setattr(va, "_shell", lambda cmd, timeout=None: "ok")
        monkeypatch.setattr(va, "_run", lambda cmd, timeout=None: "ok")
        out = va.hardening_check()
        assert isinstance(out, str) and out


# ===========================================================================
# threat_intel.py  (HTTP APIs — gated by env var)
# ===========================================================================


@pytest.mark.unit
class TestThreatIntel:
    def test_virustotal_requires_api_key(self, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        out = ti.virustotal_lookup("hash", "deadbeef")
        assert "[ERROR]" in out and "VIRUSTOTAL_API_KEY" in out

    def test_abuseipdb_requires_api_key(self, monkeypatch):
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        out = ti.abuseipdb_check("1.2.3.4")
        assert "[ERROR]" in out and "ABUSEIPDB_API_KEY" in out

    def test_virustotal_unknown_type(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "x")
        out = ti.virustotal_lookup("bogus", "value")
        assert "[ERROR]" in out

    def test_virustotal_parses_malicious_hash(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "x")
        fake_json = (
            '{"data":{"attributes":{"last_analysis_stats":'
            '{"malicious":5,"harmless":60},"type_description":"PE",'
            '"meaningful_name":"evil.exe","size":1024}}}'
        )
        monkeypatch.setattr(ti, "_http_get", lambda url, headers=None, timeout=15: fake_json)
        out = ti.virustotal_lookup("hash", "deadbeef")
        assert "MALICIOUS" in out
        assert "5/" in out

    def test_virustotal_handles_bad_json(self, monkeypatch):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "x")
        monkeypatch.setattr(ti, "_http_get", lambda url, headers=None, timeout=15: "not json")
        out = ti.virustotal_lookup("hash", "deadbeef")
        assert "[ERROR]" in out


# ===========================================================================
# threat_hunting.py
# ===========================================================================


@pytest.mark.unit
class TestThreatHunting:
    def test_ioc_search_empty_value(self):
        assert th.ioc_search("ip", "   ").startswith("[ERROR]")

    def test_ioc_search_ip_quotes_value(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(th, "_shell", cap)
        th.ioc_search("ip", "1.2.3.4; rm -rf /")
        # The whole untrusted value must be quoted in every command.
        assert "'1.2.3.4; rm -rf /'" in cap.all

    def test_ioc_search_hash_selects_algorithm(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(th, "_shell", cap)
        th.ioc_search("hash", "a" * 64)  # 64 hex chars => sha256
        assert "sha256sum" in cap.all

    def test_suspicious_files_rejects_traversal(self):
        assert th.suspicious_files(directory="../../etc").startswith("[ERROR]")

    def test_suspicious_files_caps_days(self, monkeypatch):
        cap = Capture()
        monkeypatch.setattr(th, "_shell", cap)
        th.suspicious_files(directory="/tmp", days=999)
        assert "-ctime -30" in cap.all  # capped at 30
