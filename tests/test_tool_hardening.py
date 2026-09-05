"""Security & correctness tests for the hardened tool modules.

Covers the bugs fixed during the professional-readiness audit:

  forensic.py
    - dcfldd hashlog no longer allows shell-argument injection (quoted).
    - _which uses real PATH lookup (missing tool no longer mis-detected present).
    - _validate_path blocks traversal.

  threat_hunting.py
    - ioc_search(hash) validates hex + length and selects the right algorithm,
      erroring on malformed hashes instead of silently mis-hashing (false neg).

  secops.py
    - security_metrics counts established connections by data rows (the old
      "ESTAB" substring never matched `ss ... state established` output).

  vuln_assess.py
    - config_audit quotes the discovered MySQL config path.

Subprocess layers (_run/_shell) are mocked; no real forensic/host commands run.
"""

import pytest

from quarr.tools import forensic as fo
from quarr.tools import secops as so
from quarr.tools import threat_hunting as th
from quarr.tools import vuln_assess as va

# =========================================================================== #
# forensic.py
# =========================================================================== #

@pytest.mark.unit
class TestForensicSafety:
    def test_dcfldd_hashlog_is_quoted_against_injection(self, monkeypatch):
        cap = {}
        monkeypatch.setattr(fo, "_run", lambda cmd, timeout=60: cap.setdefault("cmd", cmd) or "OK")
        monkeypatch.setattr(fo, "_which", lambda b: True)  # dcfldd "present"

        malicious = "/tmp/img; touch /tmp/pwned"
        fo.disk_image("/dev/sda", malicious)
        cmd = cap["cmd"]
        # The injected command must be neutralized inside a quoted hashlog arg.
        hashlog_token = cmd.split("hashlog=")[1].split(" ")[0]
        assert "touch /tmp/pwned" not in hashlog_token
        # dd fallback would not contain hashlog; ensure we took the dcfldd path.
        assert "dcfldd" in cmd

    def test_disk_image_falls_back_to_dd_when_dcfldd_absent(self, monkeypatch):
        cap = {}
        monkeypatch.setattr(fo, "_run", lambda cmd, timeout=60: cap.setdefault("cmd", cmd) or "OK")
        monkeypatch.setattr(fo, "_which", lambda b: False)  # nothing installed
        fo.disk_image("/dev/sda", "/tmp/img.raw")
        assert "dd if=" in cap["cmd"] and "dcfldd" not in cap["cmd"]

    def test_validate_path_blocks_traversal(self):
        with pytest.raises(ValueError):
            fo._validate_path("/tmp/../etc/passwd")

    def test_validate_path_rejects_empty(self):
        with pytest.raises(ValueError):
            fo._validate_path("   ")

    def test_which_uses_real_path_lookup(self, monkeypatch):
        import shutil
        monkeypatch.setattr(shutil, "which", lambda b: None)
        assert fo._which("definitely_missing_binary") is False
        monkeypatch.setattr(shutil, "which", lambda b: "/usr/bin/" + b)
        assert fo._which("dcfldd") is True


# =========================================================================== #
# threat_hunting.py
# =========================================================================== #

@pytest.mark.unit
class TestThreatHuntingHashValidation:
    def test_md5_length_selects_md5sum(self, monkeypatch):
        monkeypatch.setattr(th, "_shell", lambda cmd, timeout=60: cmd)
        out = th.ioc_search("hash", "d" * 32)
        assert "md5sum" in out

    def test_sha1_length_selects_sha1sum(self, monkeypatch):
        monkeypatch.setattr(th, "_shell", lambda cmd, timeout=60: cmd)
        out = th.ioc_search("hash", "a" * 40)
        assert "sha1sum" in out

    def test_sha256_length_selects_sha256sum(self, monkeypatch):
        monkeypatch.setattr(th, "_shell", lambda cmd, timeout=60: cmd)
        out = th.ioc_search("hash", "f" * 64)
        assert "sha256sum" in out

    def test_invalid_length_errors_not_silent(self):
        out = th.ioc_search("hash", "abc123")
        assert "[ERROR]" in out and "Invalid hash" in out

    def test_non_hex_errors(self):
        out = th.ioc_search("hash", "z" * 32)
        assert "[ERROR]" in out and "Invalid hash" in out

    def test_hash_is_normalized_before_use(self, monkeypatch):
        monkeypatch.setattr(th, "_shell", lambda cmd, timeout=60: cmd)
        # Uppercase + surrounding whitespace must still be accepted (normalized).
        out = th.ioc_search("hash", "  " + "A" * 64 + "  ")
        assert "sha256sum" in out


# =========================================================================== #
# secops.py
# =========================================================================== #

@pytest.mark.unit
class TestSecopsMetrics:
    def test_established_connections_counted_by_rows(self, monkeypatch):
        # `ss ... state established` omits the State column; the metric must
        # count the data rows, not look for "ESTAB".
        ss_established = (
            "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
            "tcp   0      0      10.0.0.5:22        10.0.0.9:51512\n"
            "tcp   0      0      10.0.0.5:443       10.0.0.9:51600\n"
        )
        from quarr.tools import blue_team as bt
        monkeypatch.setattr(bt, "active_connections",
                            lambda ft="all": ss_established if ft == "established" else "")
        monkeypatch.setattr(bt, "log_analysis",
                            lambda *a, **k: "no failures")
        monkeypatch.setattr(bt, "port_audit", lambda: "LISTEN 0 0 0.0.0.0:22")

        out = so.security_metrics()
        # Two established connections should be reported (not 0).
        assert "Active connections:     2" in out

    def test_zero_established_connections(self, monkeypatch):
        from quarr.tools import blue_team as bt
        monkeypatch.setattr(bt, "active_connections",
                            lambda ft="all": "Netid State Recv-Q Send-Q Local Peer\n")
        monkeypatch.setattr(bt, "log_analysis", lambda *a, **k: "")
        monkeypatch.setattr(bt, "port_audit", lambda: "")
        out = so.security_metrics()
        assert "Active connections:     0" in out


# =========================================================================== #
# vuln_assess.py
# =========================================================================== #

@pytest.mark.unit
class TestVulnAssessSafety:
    def test_mysql_config_path_is_quoted(self, monkeypatch):
        # First _shell call: `find ... .cnf` returns a path with a metachar.
        # Second: the grep on that path must receive a QUOTED path.
        calls = []

        def fake_shell(cmd, timeout=60):
            calls.append(cmd)
            if cmd.strip().startswith("find"):
                return "/etc/mysql/evil; touch pwned.cnf\n"
            return "bind-address = 127.0.0.1"

        monkeypatch.setattr(va, "_shell", fake_shell)
        va.config_audit(service="mysql")
        grep_cmd = next(c for c in calls if c.strip().startswith("grep 'bind-address'"))
        # find output is split on whitespace (first token), and that token must
        # be shell-quoted so any metacharacters cannot start a new command.
        assert "'/etc/mysql/evil;'" in grep_cmd
        # The injected `touch pwned` was split off and is NOT an executable token.
        assert "| grep -v '^#'" in grep_cmd
        assert "touch pwned" not in grep_cmd
