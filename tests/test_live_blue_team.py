"""Live Blue Team harness — real blue-team tools on the LOCAL host (opt-in).

Unlike test_blue_team_scenarios.py (which mocks the subprocess layer), this tier
runs the ACTUAL commands (ss, ps, tail, find, systemctl, who, ...) against the
machine the tests run on, and asserts the tools produce well-formed, non-crashing
output on a real system.

    ┌──────────────┬─────────────────────────────────────────────────────────┐
    │ scenarios    │ mocked _run/_shell, canned output -> detection logic      │
    │ LIVE (here)  │ real commands on this host        -> it actually works    │
    └──────────────┴─────────────────────────────────────────────────────────┘

SAFETY / OPT-IN
---------------
Every test is marked `@pytest.mark.live`; the default config runs `-m 'not live'`
so these NEVER run in CI or a normal `pytest`. They also require an explicit
env opt-in and only touch the LOCAL host (read-only inspection):

    export QUARR_LIVE_BLUE=1
    pytest tests/test_live_blue_team.py -m live -v

Read-only tools (safe): firewall_status, log_analysis, active_connections,
port_audit, process_monitor, service_audit, user_audit, cron_audit,
file_integrity_check.

STATE-CHANGING tools (firewall_block / firewall_unblock) are gated behind a
SECOND, separate opt-in because they modify iptables and need root:

    export QUARR_LIVE_BLUE_MUTATE=1   # only if you accept iptables changes

Even then the test blocks/unblocks a TEST-NET IP (203.0.113.0/24, RFC 5737)
and always cleans up.
"""

import os
import shutil

import pytest

from quarr.tools import blue_team as bt

pytestmark = pytest.mark.live

BLUE_ENABLED = os.environ.get("QUARR_LIVE_BLUE") == "1"
MUTATE_ENABLED = os.environ.get("QUARR_LIVE_BLUE_MUTATE") == "1"

# RFC 5737 TEST-NET-3 — safe, non-routable documentation range.
TEST_IP = "203.0.113.42"

if not BLUE_ENABLED:
    pytest.skip(
        "QUARR_LIVE_BLUE not set — skipping live blue-team harness. "
        "See module docstring to opt in.",
        allow_module_level=True,
    )


def require(binary: str):
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed on this host")


def assert_no_crash(out: str):
    """A live blue-team call must return a string and never raise."""
    assert isinstance(out, str)
    assert out.strip() != ""


# ===========================================================================
# Read-only inspection (safe on any host you control)
# ===========================================================================

@pytest.mark.live
class TestLiveReadOnly:
    def test_active_connections_listening(self):
        require("ss")
        out = bt.active_connections("listening")
        assert_no_crash(out)
        # A real host almost always has at least one listening socket line,
        # or a graceful "[No output]" — never a crash.
        assert "[ERROR]" not in out

    def test_port_audit_runs(self):
        require("ss")
        out = bt.port_audit()
        assert_no_crash(out)
        assert "[ERROR]" not in out

    def test_process_monitor_lists_processes(self):
        require("ps")
        out = bt.process_monitor()
        assert_no_crash(out)
        # The init/systemd process (PID 1) should appear in a top-CPU listing
        # or at least the header — the command must have executed.
        assert "[ERROR]" not in out

    def test_process_monitor_filter(self):
        require("ps")
        # Filtering for a very common process; may legitimately be empty.
        out = bt.process_monitor(filter_pattern="python")
        assert isinstance(out, str)

    def test_service_audit_runs(self):
        require("systemctl")
        out = bt.service_audit()
        assert_no_crash(out)
        assert "RUNNING SERVICES" in out

    def test_user_audit_runs(self):
        require("who")
        out = bt.user_audit()
        assert_no_crash(out)
        assert "ACTIVE SESSIONS" in out

    def test_cron_audit_runs(self):
        out = bt.cron_audit()
        assert_no_crash(out)
        assert "SYSTEM CRON" in out

    def test_log_analysis_auth_or_graceful(self):
        # auth.log may be unreadable without root — must fail gracefully, not crash.
        out = bt.log_analysis(log_type="auth", lines=20)
        assert isinstance(out, str)

    def test_file_integrity_check_bin(self):
        require("find")
        out = bt.file_integrity_check(directory="/usr/bin", days=3650)
        assert_no_crash(out)
        assert "MODIFIED IN LAST" in out

    def test_firewall_status_runs(self):
        # ufw/iptables may need root; either way it returns a string, no crash.
        out = bt.firewall_status()
        assert isinstance(out, str)


# ===========================================================================
# State-changing (iptables) — double opt-in + always cleans up
# ===========================================================================

@pytest.mark.live
@pytest.mark.skipif(
    not MUTATE_ENABLED,
    reason="QUARR_LIVE_BLUE_MUTATE not set — skipping iptables-mutating test",
)
class TestLiveFirewallMutation:
    def test_block_then_unblock_testnet_ip(self):
        require("iptables")
        try:
            blocked = bt.firewall_block(TEST_IP)
            # Root/permission problems are acceptable → assert graceful behavior.
            if "[ERROR]" in blocked:
                pytest.skip(f"cannot modify iptables here: {blocked.strip()}")
            assert blocked.startswith("✅ Blocked")
        finally:
            # Always attempt cleanup so we never leave a lingering DROP rule.
            bt.firewall_unblock(TEST_IP)

    def test_firewall_block_rejects_injection_even_live(self):
        # Validation must reject metacharacters before any command runs.
        out = bt.firewall_block(f"{TEST_IP}; touch /tmp/pwned")
        assert "[ERROR]" in out and "Invalid IP" in out
