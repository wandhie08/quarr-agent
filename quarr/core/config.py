"""
config.py - Centralized Configuration (pydantic-settings)

Loads configuration from environment variables (prefix QUARR_) and .env files,
with typed validation and cross-field runtime validation.

Legacy bare variables (OPENAI_API_KEY, OPENAI_MODEL, OLLAMA_MODEL, and the
threat-intel keys) remain supported via field aliases so existing .env files
keep working.
"""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from quarr.core.exceptions import ConfigValidationError

OLLAMA_DEFAULT_MODEL = "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest"
OPENAI_DEFAULT_MODEL = "gpt-4o-mini"


class Settings(BaseSettings):
    """QUARR runtime configuration."""

    model_config = SettingsConfigDict(
        env_prefix="QUARR_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    # --- LLM backend ---
    llm_backend: Literal["auto", "openai", "ollama"] = "auto"
    openai_api_key: str = Field(default="", validation_alias="OPENAI_API_KEY")
    openai_model: str = Field(default=OPENAI_DEFAULT_MODEL, validation_alias="OPENAI_MODEL")
    ollama_model: str = Field(default=OLLAMA_DEFAULT_MODEL, validation_alias="OLLAMA_MODEL")
    llm_timeout: float = 120.0
    llm_max_retries: int = 3

    # --- Resilience ---
    rate_limit_tpm: int = 60
    rate_limit_burst: int = 10
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 30.0
    backoff_initial: float = 1.0
    backoff_max: float = 60.0
    backoff_multiplier: float = 2.0

    # --- Logging / audit ---
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    audit_log_path: str = "audit.log"
    audit_max_bytes: int = 10_485_760
    audit_backups: int = 5

    # --- Threat intel (optional, kept for compatibility) ---
    virustotal_api_key: str = Field(default="", validation_alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str = Field(default="", validation_alias="ABUSEIPDB_API_KEY")
    shodan_api_key: str = Field(default="", validation_alias="SHODAN_API_KEY")

    # --- Security (Phase 4) ---
    secret_provider: Literal["env", "vault"] = "env"
    vault_addr: str = ""
    vault_token: str = ""
    vault_mount: str = "secret"
    allow_private_targets: bool = True
    max_targets: int = 256
    max_rate_per_min: int = 120
    session_role: Literal["viewer", "operator", "admin"] = "operator"
    auto_approve_dangerous: bool = False

    # ------------------------------------------------------------------
    def resolved_backend(self) -> str:
        """Resolve 'auto' to a concrete backend based on available credentials."""
        if self.llm_backend != "auto":
            return self.llm_backend
        return "openai" if self.openai_api_key else "ollama"

    def validate_runtime(self) -> None:
        """Cross-field validation. Raises ConfigValidationError on failure."""
        backend = self.resolved_backend()

        if backend == "openai" and not self.openai_api_key:
            raise ConfigValidationError(
                "OpenAI backend selected but OPENAI_API_KEY is empty",
                context={"field": "OPENAI_API_KEY", "expected_type": "non-empty str"},
            )

        checks = [
            ("llm_timeout", self.llm_timeout > 0, "> 0"),
            ("llm_max_retries", self.llm_max_retries >= 0, ">= 0"),
            ("rate_limit_tpm", self.rate_limit_tpm > 0, "> 0"),
            ("rate_limit_burst", self.rate_limit_burst > 0, "> 0"),
            ("circuit_breaker_threshold", self.circuit_breaker_threshold >= 1, ">= 1"),
            ("circuit_breaker_timeout", self.circuit_breaker_timeout > 0, "> 0"),
            ("backoff_initial", self.backoff_initial > 0, "> 0"),
            ("backoff_max", self.backoff_max >= self.backoff_initial, ">= backoff_initial"),
            ("backoff_multiplier", self.backoff_multiplier > 1, "> 1"),
        ]
        for field, ok, expected in checks:
            if not ok:
                raise ConfigValidationError(
                    f"Configuration value out of range: {field}",
                    context={"field": field, "expected": expected, "value": getattr(self, field)},
                )

    def redacted_summary(self) -> dict:
        """Config summary for logging with secrets masked."""
        masked = "***REDACTED***"
        return {
            "llm_backend": self.resolved_backend(),
            "openai_model": self.openai_model,
            "ollama_model": self.ollama_model,
            "openai_api_key": masked if self.openai_api_key else "",
            "virustotal_api_key": masked if self.virustotal_api_key else "",
            "abuseipdb_api_key": masked if self.abuseipdb_api_key else "",
            "shodan_api_key": masked if self.shodan_api_key else "",
            "llm_timeout": self.llm_timeout,
            "llm_max_retries": self.llm_max_retries,
            "rate_limit_tpm": self.rate_limit_tpm,
            "circuit_breaker_threshold": self.circuit_breaker_threshold,
            "circuit_breaker_timeout": self.circuit_breaker_timeout,
            "log_level": self.log_level,
            "log_format": self.log_format,
            "audit_log_path": self.audit_log_path,
        }


# ============================================================
# Secret providers (Phase 4)
# ============================================================


class SecretProvider:
    """Interface for resolving secrets from a backing store."""

    def get(self, key: str) -> str | None:  # pragma: no cover - interface
        raise NotImplementedError


class EnvSecretProvider(SecretProvider):
    def get(self, key: str) -> str | None:
        import os

        return os.environ.get(key)


class VaultSecretProvider(SecretProvider):
    """HashiCorp Vault provider (optional, lazily imports hvac)."""

    def __init__(self, addr: str, token: str, mount: str = "secret"):
        try:
            import hvac
        except ImportError as e:
            raise ConfigValidationError(
                "Vault provider requires the 'hvac' package",
                context={"field": "secret_provider"},
            ) from e
        self._client = hvac.Client(url=addr, token=token)
        self._mount = mount
        if not self._client.is_authenticated():
            raise ConfigValidationError(
                "Vault authentication failed",
                context={"field": "vault_token", "addr": addr},
            )

    def get(self, key: str) -> str | None:  # pragma: no cover - needs live vault
        try:
            resp = self._client.secrets.kv.v2.read_secret_version(path=key, mount_point=self._mount)
            return resp["data"]["data"].get("value")
        except Exception:
            return None


def build_secret_provider(settings: "Settings") -> SecretProvider:
    if settings.secret_provider == "vault":
        return VaultSecretProvider(settings.vault_addr, settings.vault_token, settings.vault_mount)
    return EnvSecretProvider()
