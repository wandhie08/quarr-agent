"""Unit tests for the secure subprocess executor (Phase 2, Req 2)."""

import pytest

from quarr.tools.executor import SecureExecutor, ExecResult
from quarr.core.exceptions import (
    ArgumentValidationError, ToolNotFoundError, ToolTimeoutError,
)


@pytest.mark.unit
def test_echo_happy_path():
    ex = SecureExecutor()
    result = ex.run(["echo", "hello_world"], timeout=5)
    assert isinstance(result, ExecResult)
    assert result.exit_code == 0
    assert "hello_world" in result.stdout


@pytest.mark.unit
@pytest.mark.parametrize("bad", [
    "; rm -rf /",
    "a|b",
    "$(whoami)",
    "`id`",
    "a>b",
    "a b",          # space would split into two shell words
    "a&b",
    "new\nline",
])
def test_injection_payloads_rejected(bad):
    ex = SecureExecutor()
    with pytest.raises(ArgumentValidationError):
        ex.run(["echo", bad], timeout=5)


@pytest.mark.unit
def test_empty_argv_rejected():
    ex = SecureExecutor()
    with pytest.raises(ArgumentValidationError):
        ex.run([], timeout=5)


@pytest.mark.unit
def test_missing_binary_raises():
    ex = SecureExecutor()
    with pytest.raises(ToolNotFoundError):
        ex.run(["definitely_not_a_real_binary_xyz"], timeout=5)


@pytest.mark.unit
def test_timeout_raises():
    ex = SecureExecutor()
    with pytest.raises(ToolTimeoutError):
        ex.run(["sleep", "5"], timeout=1)


@pytest.mark.unit
def test_valid_flags_and_values_pass_validation():
    ex = SecureExecutor()
    # These should pass the allowlist (validation happens before exec).
    ex.validate_argv(["nmap", "-sV", "-oX", "-", "10.0.0.1"])
    ex.validate_argv(["nuclei", "-u", "https://example.com", "-jsonl"])
