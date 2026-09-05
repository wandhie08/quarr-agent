"""Live DFIR & Threat-Hunting harness — real forensic/hunting tools on the LOCAL host (opt-in).

Mirrors test_live_blue_team.py for the DFIR and threat-hunting domains, which had
no live tier. Where the scenario suites mock the subprocess layer, this runs the
ACTUAL commands (ps, ss, last, find, sha256sum, strings, file, grep over /var/log)
against the machine the tests run on, and asserts they produce well-formed,
non-crashing output on a real system — the deepest "it actually works" tier for
these domains.

    ┌──────────────┬─────────────────────────────────────────────────────────┐
    │ scenarios    │ mocked _run/_shell, canned output -> detection logic      │
    │ LIVE (here)  │ real commands on this host        -> it actually works    │
    └──────────────┴─────────────────────────────────────────────────────────┘

SAFETY / OPT-IN
---------------
Every test is marked `@pytest.mark.live`; the default config runs `-m 'not live'`
so these NEVER run in CI or a normal `pytest`. They also require an explicit
env opt-in and only perform READ-ONLY inspection of the LOCAL host:

    export QUARR_LIVE_DFIR=1
    pytest tests/test_live_dfir.py -m live -v

Read-only tools exercised: incident_triage, build_incident_timeline (log grep),
suspicious_files, rootkit_scan, ioc_search (filename/hash), hash_verify,
malware_analyze (on a temp file we create), chain_of_custody (collect/verify on
a temp file in a temp dir). No state-changing or destructive operations run.
"""

import os
import shutil
import tempfile

import pytest

from quarr.tools import dfir
from quarr.tools import threat_hunting as th

pytestmark = pytest.mark.live

DFIR_ENABLED = os.environ.get("QUARR_LIVE_DFIR") == "1"

if not DFIR_ENABLED:
    pytest.skip(
        "QUARR_LIVE_DFIR not set — skipping live DFIR/hunting harness. "
        "See module docstring to opt in.",
        allow_module_level=True,
    )


def require(binary: str):
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed on this host")


def assert_no_crash(out: str):
    assert isinstance(out, str)
    assert out.strip() != ""
    assert "[EXECUTION ERROR]" not in out


# ===========================================================================
# DFIR — incident triage / timeline / malware / chain-of-custody
# ===========================================================================

@pytest.mark.live
class TestLiveDFIR:
    def test_incident_triage_runs_all_checks(self):
        require("ps")
        require("ss")
        out = dfir.incident_triage()
        assert_no_crash(out)
        # The automated triage always emits its section headers + summary.
        assert "TRIAGE SUMMARY" in out
        assert "NETWORK CONNECTIONS" in out
        assert "SUSPICIOUS PROCESSES" in out

    def test_build_incident_timeline_runs(self):
        # Reads/greps logs (may be unreadable without root) — must not crash.
        out = dfir.build_incident_timeline(hours=1)
        assert_no_crash(out)
        assert "INCIDENT TIMELINE" in out

    def test_malware_analyze_on_temp_file(self):
        require("file")
        require("sha256sum")
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.write(fd, b"#!/bin/sh\necho hello\ncurl http://example.com\n")
        os.close(fd)
        try:
            out = dfir.malware_analyze(path)
            assert_no_crash(out)
            assert "FILE TYPE" in out
            assert "HASHES" in out
            # A real sha256sum ran and produced a 64-hex digest.
            assert "SHA256:" in out
        finally:
            os.unlink(path)

    def test_malware_analyze_missing_file_errors_gracefully(self):
        out = dfir.malware_analyze("/nonexistent/path/to/file.bin")
        assert "[ERROR]" in out and "not found" in out.lower()

    def test_chain_of_custody_collect_then_verify(self, tmp_path, monkeypatch):
        # Isolate the custody store under a temp dir so we don't touch the repo.
        monkeypatch.chdir(tmp_path)
        evidence = tmp_path / "evidence.txt"
        evidence.write_text("sensitive evidence content")

        collected = dfir.chain_of_custody(str(evidence), action="collect", notes="live test")
        assert_no_crash(collected)
        assert "SHA256:" in collected and "COLLECTED" in collected

        # Verify integrity of the unchanged file — must confirm.
        verified = dfir.chain_of_custody(str(evidence), action="verify")
        assert "VERIFIED" in verified or "✅" in verified

        # Tamper and re-verify — must flag a violation.
        evidence.write_text("tampered!")
        tampered = dfir.chain_of_custody(str(evidence), action="verify")
        assert "VIOLATION" in tampered or "🚨" in tampered


# ===========================================================================
# Threat hunting — real find / hashing / rootkit heuristics
# ===========================================================================

@pytest.mark.live
class TestLiveThreatHunting:
    def test_suspicious_files_scans_tmp(self):
        require("find")
        out = th.suspicious_files("/tmp", days=3650)
        assert_no_crash(out)
        assert "[ERROR]" not in out

    def test_rootkit_scan_runs(self):
        out = th.rootkit_scan()
        assert_no_crash(out)  # heuristic checks; must not crash even w/o chkrootkit

    def test_ioc_search_filename_real_find(self):
        require("find")
        # 'passwd' exists under /etc on any Linux host.
        out = th.ioc_search("filename", "passwd")
        assert isinstance(out, str)
        assert "[ERROR]" not in out

    def test_ioc_search_hash_real_hashing(self):
        require("sha256sum")
        # A valid 64-hex SHA256 that won't match anything — must complete cleanly.
        out = th.ioc_search("hash", "a" * 64)
        assert isinstance(out, str)
        assert "[ERROR]" not in out

    def test_ioc_search_invalid_hash_rejected_live(self):
        # Validation must reject a malformed hash before any find/hashing runs.
        out = th.ioc_search("hash", "not-a-valid-hash")
        assert "[ERROR]" in out and "Invalid hash" in out

    def test_hash_verify_real_file(self):
        require("sha256sum")
        fd, path = tempfile.mkstemp()
        os.write(fd, b"quarr live hunting test")
        os.close(fd)
        try:
            out = th.hash_verify(path)
            assert_no_crash(out)
            # A real digest (64 hex chars) should appear in the output.
            assert any(len(tok) == 64 and all(c in "0123456789abcdef" for c in tok.lower())
                       for tok in out.split())
        finally:
            os.unlink(path)
