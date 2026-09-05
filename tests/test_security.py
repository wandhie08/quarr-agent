"""Unit tests for Phase 4 security components."""


import pytest

from quarr.core import permissions, secrets
from quarr.core.approval import ApprovalWorkflow
from quarr.core.config import EnvSecretProvider, Settings, build_secret_provider
from quarr.core.exceptions import ConfigValidationError, PolicyViolationError
from quarr.core.logging import configure_logging, get_logger
from quarr.core.models import Engagement, RiskLevel
from quarr.core.policy import PolicyEngine
from quarr.core.scope import ScopeLimiter

# ---- secrets ----

@pytest.mark.unit
@pytest.mark.parametrize("text", [
    "AKIAIOSFODNN7EXAMPLE",
    "token sk-abcdefghijklmnopqrstuvwx",
    "Authorization: Bearer abcdef1234567890",
    "password: hunter2",
    "api_key = deadbeefcafe",
])
def test_secrets_detected(text):
    assert len(secrets.detect(text)) >= 1


@pytest.mark.unit
def test_secrets_negative():
    assert secrets.detect("just a normal log line with host 10.0.0.1") == []


@pytest.mark.unit
def test_redact_masks_values():
    out = secrets.redact("password: hunter2 and api_key=deadbeef")
    assert "hunter2" not in out
    assert "deadbeef" not in out
    assert "***REDACTED***" in out


@pytest.mark.unit
def test_seeded_secret_absent_from_logs(capsys):
    configure_logging(level="INFO", fmt="json")
    log = get_logger("quarr.sec")
    log.info("event", password="topsecret123")
    err = capsys.readouterr().err
    assert "topsecret123" not in err


# ---- secret provider ----

@pytest.mark.unit
def test_env_provider(monkeypatch):
    monkeypatch.setenv("MYKEY", "val")
    assert EnvSecretProvider().get("MYKEY") == "val"


@pytest.mark.unit
def test_build_provider_default_is_env():
    s = Settings(_env_file=None)
    assert isinstance(build_secret_provider(s), EnvSecretProvider)


@pytest.mark.unit
def test_vault_provider_unreachable_raises(monkeypatch):
    s = Settings(_env_file=None, secret_provider="vault",
                 vault_addr="http://127.0.0.1:1", vault_token="bad")

    class FakeClient:
        def __init__(self, *a, **k): pass
        def is_authenticated(self): return False

    import sys
    import types
    fake_hvac = types.ModuleType("hvac")
    fake_hvac.Client = FakeClient
    monkeypatch.setitem(sys.modules, "hvac", fake_hvac)
    with pytest.raises(ConfigValidationError):
        build_secret_provider(s)


# ---- permissions ----

@pytest.mark.unit
def test_permission_allows_operator_medium():
    permissions.check("operator", RiskLevel.MEDIUM, "nmap")  # no raise


@pytest.mark.unit
def test_permission_denies_viewer_critical():
    with pytest.raises(PolicyViolationError):
        permissions.check("viewer", RiskLevel.CRITICAL, "hashcat")


@pytest.mark.unit
def test_permission_admin_allows_critical():
    permissions.check("admin", RiskLevel.CRITICAL, "hashcat")  # no raise


# ---- scope limiter ----

@pytest.mark.unit
def test_scope_distinct_target_cap():
    eng = Engagement(name="T", allowed_targets=["10.0.0.0/8"])
    sl = ScopeLimiter(max_targets=2, max_rate_per_min=1000)
    sl.check("10.0.0.1", eng)
    sl.check("10.0.0.2", eng)
    with pytest.raises(PolicyViolationError):
        sl.check("10.0.0.3", eng)


@pytest.mark.unit
def test_scope_rate_cap():
    eng = Engagement(name="T", allowed_targets=["10.0.0.0/8"])
    clock = lambda: 0.0  # noqa: E731 - frozen clock
    sl = ScopeLimiter(max_targets=1000, max_rate_per_min=2, clock=clock)
    sl.check("10.0.0.1", eng)
    sl.check("10.0.0.1", eng)
    with pytest.raises(PolicyViolationError):
        sl.check("10.0.0.1", eng)


# ---- approval ----

@pytest.mark.unit
def test_approval_low_risk_no_prompt():
    calls = {"n": 0}
    aw = ApprovalWorkflow(prompt_fn=lambda p: calls.__setitem__("n", calls["n"] + 1) or "n")
    aw.gate("nmap", "10.0.0.1", RiskLevel.LOW)  # no prompt, no raise
    assert calls["n"] == 0


@pytest.mark.unit
def test_approval_high_risk_denied_raises():
    aw = ApprovalWorkflow(prompt_fn=lambda p: "n")
    with pytest.raises(PolicyViolationError):
        aw.gate("hydra", "10.0.0.1", RiskLevel.HIGH)


@pytest.mark.unit
def test_approval_high_risk_approved():
    aw = ApprovalWorkflow(prompt_fn=lambda p: "y")
    aw.gate("hydra", "10.0.0.1", RiskLevel.HIGH)  # no raise


@pytest.mark.unit
def test_approval_auto_approve_bypasses():
    aw = ApprovalWorkflow(auto_approve=True)
    aw.gate("hashcat", "10.0.0.1", RiskLevel.CRITICAL)  # no raise


# ---- policy integration ----

@pytest.mark.unit
def test_policy_pipeline_permission_then_scope_then_approval():
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"],
                     allowed_operations=[])
    # viewer + CRITICAL → permission denies before anything else.
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize(
            "hashcat", {"target": "10.10.10.5"}, eng,
            role="viewer", tool_risk=RiskLevel.CRITICAL,
        )


@pytest.mark.unit
def test_policy_backward_compatible_call():
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"],
                     allowed_operations=[])
    # Old-style call (no Phase 4 kwargs) still works.
    assert PolicyEngine.authorize("network_discovery", {"target": "10.10.10.5"}, eng)


@pytest.mark.unit
def test_policy_approval_gate_integration():
    eng = Engagement(name="T", allowed_targets=["10.10.10.0/24"],
                     allowed_operations=[])
    aw = ApprovalWorkflow(prompt_fn=lambda p: "n")
    with pytest.raises(PolicyViolationError):
        PolicyEngine.authorize(
            "hydra", {"target": "10.10.10.5"}, eng,
            role="operator", tool_risk=RiskLevel.HIGH, approval=aw,
        )
