"""Unit tests for the custom exception hierarchy (Phase 1, Req 1)."""

import pytest

from quarr.core.exceptions import (
    QuarrError,
    LLMError, LLMConnectionError, LLMTimeoutError, LLMRateLimitError, LLMResponseError,
    ToolError, ToolNotFoundError, ToolExecutionError, ToolTimeoutError, ToolOutputParseError,
    ValidationError, ConfigValidationError, TargetValidationError, ArgumentValidationError,
    PolicyViolationError,
)


@pytest.mark.unit
def test_base_inheritance():
    assert issubclass(LLMError, QuarrError)
    assert issubclass(ToolError, QuarrError)
    assert issubclass(ValidationError, QuarrError)
    assert issubclass(PolicyViolationError, QuarrError)


@pytest.mark.unit
def test_llm_subclasses():
    for cls in (LLMConnectionError, LLMTimeoutError, LLMRateLimitError, LLMResponseError):
        assert issubclass(cls, LLMError)


@pytest.mark.unit
def test_tool_subclasses():
    for cls in (ToolNotFoundError, ToolExecutionError, ToolTimeoutError, ToolOutputParseError):
        assert issubclass(cls, ToolError)


@pytest.mark.unit
def test_validation_subclasses():
    for cls in (ConfigValidationError, TargetValidationError, ArgumentValidationError):
        assert issubclass(cls, ValidationError)


@pytest.mark.unit
def test_to_dict_shape():
    cause = ValueError("root cause")
    err = LLMTimeoutError(
        "request timed out",
        context={"elapsed": 5.0, "timeout": 3.0},
        cause=cause,
    )
    d = err.to_dict()
    assert d["type"] == "LLMTimeoutError"
    assert d["error_code"] == "LLMTimeoutError"
    assert d["message"] == "request timed out"
    assert d["context"] == {"elapsed": 5.0, "timeout": 3.0}
    assert "root cause" in d["cause"]


@pytest.mark.unit
def test_default_error_code_and_empty_context():
    err = ToolNotFoundError("nmap missing")
    d = err.to_dict()
    assert d["error_code"] == "ToolNotFoundError"
    assert d["context"] == {}
    assert d["cause"] is None


@pytest.mark.unit
def test_custom_error_code():
    err = ConfigValidationError("bad", error_code="E_CONFIG", context={"field": "x"})
    assert err.error_code == "E_CONFIG"
    assert err.context["field"] == "x"


@pytest.mark.unit
def test_str_includes_context():
    err = ArgumentValidationError("bad arg", context={"arg": ";rm"})
    assert "bad arg" in str(err)
    assert "arg" in str(err)
