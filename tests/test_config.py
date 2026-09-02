"""Unit tests for configuration management (Phase 1, Req 7 & 9)."""

import pytest

from quarr.core.config import Settings
from quarr.core.exceptions import ConfigValidationError


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    # Ensure a clean, deterministic environment (no .env leakage).
    for var in [
        "OPENAI_API_KEY", "OPENAI_MODEL", "OLLAMA_MODEL",
        "QUARR_LLM_BACKEND", "QUARR_LOG_LEVEL", "QUARR_LLM_TIMEOUT",
        "QUARR_LLM_MAX_RETRIES", "VIRUSTOTAL_API_KEY",
    ]:
        monkeypatch.delenv(var, raising=False)
    yield


def _settings(**overrides) -> Settings:
    # Bypass .env file to keep tests hermetic.
    return Settings(_env_file=None, **overrides)


@pytest.mark.unit
def test_defaults_load():
    s = _settings()
    assert s.llm_backend == "auto"
    assert s.llm_timeout == 120.0
    assert s.rate_limit_tpm == 60
    assert s.resolved_backend() == "ollama"  # no key → ollama
    s.validate_runtime()  # should not raise


@pytest.mark.unit
def test_openai_backend_without_key_raises():
    s = _settings(llm_backend="openai")
    with pytest.raises(ConfigValidationError) as ei:
        s.validate_runtime()
    assert ei.value.context["field"] == "OPENAI_API_KEY"


@pytest.mark.unit
def test_openai_backend_with_key_ok():
    s = _settings(llm_backend="openai", openai_api_key="sk-test")
    assert s.resolved_backend() == "openai"
    s.validate_runtime()


@pytest.mark.unit
def test_out_of_range_raises():
    s = _settings(llm_timeout=-1)
    with pytest.raises(ConfigValidationError) as ei:
        s.validate_runtime()
    assert ei.value.context["field"] == "llm_timeout"


@pytest.mark.unit
def test_redacted_summary_masks_keys():
    s = _settings(openai_api_key="sk-secret")
    summary = s.redacted_summary()
    assert summary["openai_api_key"] == "***REDACTED***"
    assert "sk-secret" not in str(summary)


@pytest.mark.unit
def test_legacy_alias_and_quarr_prefix(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fromenv")
    monkeypatch.setenv("QUARR_LOG_LEVEL", "DEBUG")
    s = Settings(_env_file=None)
    assert s.openai_api_key == "sk-fromenv"
    assert s.log_level == "DEBUG"
    assert s.resolved_backend() == "openai"
