"""
exceptions.py - Custom Exception Hierarchy

All QUARR custom exceptions inherit from QuarrError and carry structured
attributes (error_code, context, cause) plus a to_dict() for logging/audit.

Hierarchy:

    QuarrError
    ├── LLMError
    │   ├── LLMConnectionError
    │   ├── LLMTimeoutError
    │   ├── LLMRateLimitError
    │   └── LLMResponseError
    ├── ToolError
    │   ├── ToolNotFoundError
    │   ├── ToolExecutionError
    │   ├── ToolTimeoutError
    │   └── ToolOutputParseError
    ├── ValidationError
    │   ├── ConfigValidationError
    │   ├── TargetValidationError
    │   └── ArgumentValidationError
    └── PolicyViolationError
"""

from typing import Any


class QuarrError(Exception):
    """Base class for all QUARR custom exceptions."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.cause = cause

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable representation for logging/audit."""
        return {
            "type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "cause": repr(self.cause) if self.cause is not None else None,
        }

    def __str__(self) -> str:
        if self.context:
            return f"{self.message} (context={self.context})"
        return self.message


# ============================================================
# LLM errors
# ============================================================


class LLMError(QuarrError):
    """Base for LLM backend errors."""


class LLMConnectionError(LLMError):
    """Raised when the LLM backend cannot be reached."""


class LLMTimeoutError(LLMError):
    """Raised when an LLM request exceeds its timeout."""


class LLMRateLimitError(LLMError):
    """Raised when the LLM backend rate-limits the request (HTTP 429)."""


class LLMResponseError(LLMError):
    """Raised for non-retryable HTTP errors or unparseable responses."""


# ============================================================
# Tool errors
# ============================================================


class ToolError(QuarrError):
    """Base for tool execution errors."""


class ToolNotFoundError(ToolError):
    """Raised when a required tool binary is not installed/available."""


class ToolExecutionError(ToolError):
    """Raised when a tool exits with a failure status."""


class ToolTimeoutError(ToolError):
    """Raised when a tool execution exceeds its timeout."""


class ToolOutputParseError(ToolError):
    """Raised when tool output cannot be parsed into structured data."""


# ============================================================
# Validation errors
# ============================================================


class ValidationError(QuarrError):
    """Base for input/configuration validation errors."""


class ConfigValidationError(ValidationError):
    """Raised when configuration is missing or invalid."""


class TargetValidationError(ValidationError):
    """Raised when a target string is malformed or out of policy."""


class ArgumentValidationError(ValidationError):
    """Raised when a command argument fails validation."""


# ============================================================
# Policy errors
# ============================================================


class PolicyViolationError(QuarrError):
    """Raised when an operation violates authorization/scope policy."""
