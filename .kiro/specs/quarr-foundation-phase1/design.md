# Design Document

## Overview

This document describes the technical design for **Phase 1: Foundation & Error Handling** of the QUARR Agent. The goal of this phase is to replace ad-hoc error handling, `print`/`logging.basicConfig` logging, and untyped environment-variable access with a robust, auditable, and fault-tolerant foundation.

The design introduces seven new capabilities layered onto the existing `quarr/core/` package:

1. A custom exception hierarchy (`quarr/core/exceptions.py`)
2. Structured logging with `structlog` (`quarr/core/logging.py`)
3. Immutable audit logging (`quarr/core/audit.py`)
4. Centralized configuration via `pydantic-settings` (`quarr/core/config.py`)
5. Retry with exponential backoff via `tenacity` (integrated into `llm_client.py`)
6. Token-bucket rate limiting (`quarr/core/rate_limiter.py`)
7. Circuit breaker (`quarr/core/circuit_breaker.py`)

These are wired into the existing `LLM_Client` (`quarr/core/llm_client.py`), the `QuarrAgent` loop (`quarr/core/agent.py`), the `PolicyEngine` (`quarr/core/policy.py`), and the CLI entrypoint (`main.py`).

### Design Principles

- **Non-breaking additions first.** New modules are self-contained. Existing call sites are updated incrementally so the agent keeps running at each step.
- **Fail fast at startup, degrade gracefully at runtime.** Configuration errors abort the process; transient runtime errors are retried, logged, and surfaced to the LLM as recoverable context.
- **Redaction by default.** Secrets never reach logs or audit records in plaintext.
- **Backward-compatible config.** Existing bare env vars (`OPENAI_API_KEY`, `OLLAMA_MODEL`, etc.) continue to work; new settings use the `QUARR_` prefix.

## Architecture

### Module Dependency Diagram

```
                    ┌──────────────────┐
                    │   config.py      │  (pydantic-settings)
                    │   Settings       │
                    └────────┬─────────┘
                             │ imported by all
        ┌────────────────────┼────────────────────────┐
        ▼                    ▼                         ▼
┌───────────────┐   ┌─────────────────┐      ┌──────────────────┐
│ logging.py    │   │ exceptions.py   │      │ audit.py         │
│ configure_    │   │ QuarrError tree │      │ AuditLogger      │
│ logging()     │   └────────┬────────┘      └────────┬─────────┘
└───────┬───────┘            │                        │
        │                    │                        │
        │      ┌─────────────┼────────────┐           │
        ▼      ▼             ▼            ▼            ▼
   ┌────────────────────────────────────────────────────────┐
   │                     llm_client.py                        │
   │  create_llm_client() → wraps chat() with:               │
   │    RateLimiter → CircuitBreaker → tenacity.retry         │
   │    → maps httpx errors to LLMError subclasses            │
   └────────────────────────────────────────────────────────┘
        ▲                                        ▲
        │                                        │
┌───────┴────────┐                     ┌─────────┴─────────┐
│ rate_limiter.py│                     │ circuit_breaker.py│
│ TokenBucket    │                     │ CircuitBreaker    │
└────────────────┘                     └───────────────────┘

   ┌────────────────────────────────────────────────────────┐
   │                       agent.py                           │
   │  wraps tool handler calls in try/except → logs +        │
   │  records failure in state + audit + continues loop      │
   └────────────────────────────────────────────────────────┘

   ┌────────────────────────────────────────────────────────┐
   │                        main.py                           │
   │  load Settings → configure_logging() → validate →        │
   │  init AuditLogger → construct QuarrAgent                 │
   └────────────────────────────────────────────────────────┘
```

### Runtime Flow: An LLM Call

```
agent.run()
  └─> client.chat(messages, tools)
        └─> RateLimiter.acquire()          # blocks until token available
              └─> CircuitBreaker.call(fn)  # rejects fast if OPEN
                    └─> tenacity.retry(fn) # exponential backoff
                          └─> _do_request()
                                ├─ success → return normalized dict
                                └─ httpx error → map to LLMError subclass
                                                 → log ERROR → raise
```

## Components and Interfaces

### 1. Exception Hierarchy — `quarr/core/exceptions.py`

A single base class carries structured attributes used by logging and audit.

```python
class QuarrError(Exception):
    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        context: dict | None = None,
        cause: Exception | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
        self.cause = cause

    def to_dict(self) -> dict:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "cause": repr(self.cause) if self.cause else None,
            "type": self.__class__.__name__,
        }
```

Hierarchy (Req 1):

```
QuarrError
├── LLMError
│   ├── LLMConnectionError
│   ├── LLMTimeoutError        # context: {elapsed, timeout}
│   ├── LLMRateLimitError      # context: {retry_after}
│   └── LLMResponseError       # context: {status_code, body}
├── ToolError
│   ├── ToolNotFoundError
│   ├── ToolExecutionError
│   ├── ToolTimeoutError
│   └── ToolOutputParseError
├── ValidationError
│   ├── ConfigValidationError  # context: {field, expected_type}
│   ├── TargetValidationError
│   └── ArgumentValidationError
└── PolicyViolationError
```

> **Compatibility note.** `quarr/core/policy.py` currently defines `PolicyViolation(Exception)`. To avoid breaking imports, `PolicyViolationError` will subclass `QuarrError`, and `policy.py` will alias `PolicyViolation = PolicyViolationError` (keeping the old name importable) or raise the new class directly. Existing `except PolicyViolation` sites in `agent.py` remain valid.

### 2. Structured Logging — `quarr/core/logging.py`

Wraps `structlog`. Called once at startup by `main.py`.

```python
def configure_logging(
    level: str = "INFO",
    fmt: str = "console",       # "console" | "json"
    redact_keys: list[str] | None = None,
) -> None: ...

def get_logger(name: str) -> structlog.BoundLogger: ...

def bind_correlation_id(cid: str | None = None) -> str: ...
```

Processor chain (Req 4):
- `structlog.contextvars.merge_contextvars` (carries correlation ID + bound vars)
- timestamp (ISO 8601, UTC)
- log level + logger name
- `_redaction_processor` (Req 5.7) — recursively redacts values whose keys match `redact_keys` (default: `api_key`, `authorization`, `password`, `secret`, `token`, `credential`) → replaced with `"***REDACTED***"`
- renderer: `ConsoleRenderer` (dev) or `JSONRenderer` (prod)

Correlation ID is stored in a `contextvars.ContextVar` and injected via `merge_contextvars`, so all logs within one agent turn share the same ID.

> **Migration note.** Existing modules use `logging.getLogger("quarr.x")`. `configure_logging()` also configures the stdlib root logger to route through structlog's `ProcessorFormatter`, so legacy `logging.getLogger` calls keep working and get the same JSON/console formatting without rewriting every module at once.

### 3. Audit Logging — `quarr/core/audit.py`

```python
class AuditLogger:
    def __init__(self, path: str, rotate_max_bytes: int, rotate_backups: int): ...
    def record_execution(self, *, tool_name, target, arguments,
                         session_id, engagement_id) -> int:   # returns seq no.
    def record_result(self, *, seq, success, duration_ms, result_summary) -> None: ...
```

Design points (Req 6):
- Writes newline-delimited JSON to a **dedicated file** separate from app logs, using a `RotatingFileHandler` (size-based rotation).
- Maintains a monotonically increasing `sequence` counter (in-memory, seeded from the last line of the existing file on init).
- Each entry stores `sha256` = SHA-256 over the canonical JSON of the entry **excluding** the hash field, giving tamper-evidence.
- Arguments are passed through the same redaction filter as logging before writing; `result_summary` is a truncated, redacted summary — never raw evidence or credentials.

### 4. Configuration — `quarr/core/config.py`

`pydantic-settings` `BaseSettings`, prefix `QUARR_`, reads `.env`.

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="QUARR_", env_file=".env", extra="ignore"
    )

    # LLM backend
    llm_backend: Literal["auto", "openai", "ollama"] = "auto"
    openai_api_key: str = Field("", alias="OPENAI_API_KEY")
    openai_model: str = Field("gpt-4o-mini", alias="OPENAI_MODEL")
    ollama_model: str = Field(OLLAMA_DEFAULT_MODEL, alias="OLLAMA_MODEL")
    llm_timeout: float = 120.0
    llm_max_retries: int = 3

    # Resilience
    rate_limit_tpm: int = 60
    rate_limit_burst: int = 10
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 30.0
    backoff_initial: float = 1.0
    backoff_max: float = 60.0
    backoff_multiplier: float = 2.0

    # Logging / audit
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    audit_log_path: str = "audit.log"
    audit_max_bytes: int = 10_485_760
    audit_backups: int = 5

    # Threat intel (optional, kept for compatibility)
    virustotal_api_key: str = Field("", alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str = Field("", alias="ABUSEIPDB_API_KEY")
    shodan_api_key: str = Field("", alias="SHODAN_API_KEY")

    def validate_runtime(self) -> None:
        """Cross-field validation → raises ConfigValidationError."""
```

`validate_runtime()` (Req 9):
- Resolves `auto` backend: OpenAI if `openai_api_key` non-empty else Ollama.
- If resolved backend is `openai` and `openai_api_key` is empty → `ConfigValidationError(field="OPENAI_API_KEY")`.
- Range checks: `llm_timeout > 0`, `llm_max_retries >= 0`, `rate_limit_tpm > 0`, `circuit_breaker_threshold >= 1`, backoff params positive.
- `redacted_summary()` returns a dict for logging with all `*_api_key` fields masked.

The dual naming (`QUARR_`-prefixed for new fields, `alias=` for legacy bare names) preserves the existing `.env` while enabling the documented `QUARR_*` variables (Req 8).

### 5. Retry — integrated into `quarr/core/llm_client.py`

Uses `tenacity` (Req 10). A retry decorator is built from `Settings`:

```python
retry(
    retry=retry_if_exception_type((LLMConnectionError, LLMTimeoutError)),
    wait=wait_exponential(multiplier=backoff_multiplier,
                          min=backoff_initial, max=backoff_max),
    stop=stop_after_attempt(llm_max_retries),
    before_sleep=_log_retry,   # WARNING: attempt, wait, error type
    reraise=True,
)
```

- `LLMResponseError` with status 400/401 is **not** retried (not in `retry_if_exception_type`).
- `LLMRateLimitError`: handled specially — if `retry_after` present, sleep that long then retry within the same attempt budget.
- On exhaustion, the final exception is re-raised with `context["retry_attempts"]` populated.

HTTP error mapping (Req 2) happens in a new `_do_request()` helper shared by `OpenAIClient` and `OllamaClient`, replacing bare `response.raise_for_status()`:

| Condition | Raised |
|---|---|
| `httpx.ConnectError`/`ConnectTimeout` | `LLMConnectionError` |
| `httpx.ReadTimeout`/elapsed > timeout | `LLMTimeoutError(context={elapsed,timeout})` |
| HTTP 429 | `LLMRateLimitError(context={retry_after})` |
| HTTP 4xx/5xx | `LLMResponseError(context={status_code,body})` |
| JSON decode failure | `LLMResponseError(context={parse_error})` |

### 6. Rate Limiter — `quarr/core/rate_limiter.py`

Token bucket (Req 11), thread-safe via `threading.Lock`, async-friendly `await acquire()`.

```python
class TokenBucket:
    def __init__(self, rate_per_minute: int, burst: int): ...
    async def acquire(self, max_wait: float = 30.0) -> None:
        # refill based on elapsed time; if a token is available consume it;
        # else compute wait; if wait > max_wait → raise LLMRateLimitError;
        # else asyncio.sleep(wait) and consume.
```

Refill formula: `tokens = min(burst, tokens + elapsed_seconds * rate_per_minute/60)`.

### 7. Circuit Breaker — `quarr/core/circuit_breaker.py`

Three-state machine (Req 12): `CLOSED → OPEN → HALF_OPEN → CLOSED/OPEN`.

```python
class CircuitBreaker:
    def __init__(self, threshold: int, window: float, reset_timeout: float): ...
    async def call(self, coro_fn, *args, **kwargs):
        # OPEN + within reset_timeout → raise LLMConnectionError("circuit open")
        # OPEN + past reset_timeout → HALF_OPEN, allow single probe
        # HALF_OPEN success → CLOSED, reset counters
        # HALF_OPEN failure → OPEN
        # CLOSED: count failures within window; exceed threshold → OPEN
```

State transitions logged at WARNING with `{from, to, reason}`. Failure timestamps tracked in a deque pruned to `window`.

## Data Models

No changes to `quarr/core/models.py` are strictly required. The existing `ToolExecution` model already captures `tool_name`, `arguments`, `success`, `timestamp`, and `result_summary`, which the `AuditLogger` consumes. If needed, an optional `duration_ms: Optional[int] = None` and `error: Optional[str] = None` field will be added to `ToolExecution` to record failures surfaced to the LLM (Req 3.2).

New in-memory structures:
- `CircuitState` enum (`CLOSED`, `OPEN`, `HALF_OPEN`).
- Audit entry dict schema: `{sequence, timestamp, event, tool_name, target, arguments, session_id, engagement_id, success, duration_ms, result_summary, sha256}`.

## Error Handling

### Agent Loop (Req 3)

In `agent.py`, the tool-dispatch section is wrapped:

```python
try:
    handler = TOOL_REGISTRY[name]
    ...
    result = handler(**args)
except PolicyViolationError as e:
    log.warning("policy_violation", tool=name, reason=str(e))
    tool_result_msg = f"POLICY VIOLATION: {e}"        # fed back to LLM
except ToolError as e:
    log.error("tool_error", **e.to_dict())
    self.state.record_tool(ToolExecution(..., success=False))
    tool_result_msg = f"TOOL ERROR: {e}"
except Exception as e:
    cid = get_correlation_id()
    log.error("unexpected_tool_error", correlation_id=cid, exc_info=True)
    tool_result_msg = f"UNEXPECTED ERROR (ref {cid}): {e}"
finally:
    consecutive_errors tracked; if >= 3 → break loop with summary
```

- Tool failures never abort the loop; they are appended as an assistant/tool message so the LLM can adapt.
- A `consecutive_errors` counter resets on success and terminates the loop at 3 (Req 3.4).
- Initialization errors (bad config, client construction) raise before the loop; `main.py` catches, logs CRITICAL, exits code 1 (Req 3.5, 9.2).

### Startup (Req 9)

`main.py` sequence:
1. `settings = Settings()` — pydantic parse.
2. `configure_logging(settings.log_level, settings.log_format)`.
3. `settings.validate_runtime()` — on `ConfigValidationError`, log CRITICAL + `sys.exit(1)`.
4. Log INFO `config_loaded` with `settings.redacted_summary()`.
5. Construct `AuditLogger` and `QuarrAgent`.

## Testing Strategy

Unit tests live under `tests/` (pytest). Phase 1 introduces the test scaffolding that Phase 3 expands.

- **exceptions**: `to_dict()` shape, inheritance, context/cause propagation.
- **config**: valid load; missing OpenAI key with openai backend → `ConfigValidationError`; range validation; `redacted_summary()` masks keys; `QUARR_`-prefixed and legacy aliases both parse (via `monkeypatch.setenv`).
- **logging**: redaction processor masks nested secret keys; correlation ID propagates across bound loggers; JSON vs console format selection.
- **audit**: sequence increments and persists across re-init; SHA-256 present and stable; redaction applied; rotation triggers at size threshold (small `max_bytes` in test).
- **rate_limiter**: burst allowed immediately; over-limit waits; wait > max_wait raises `LLMRateLimitError`; refill math. Use monkeypatched clock / `asyncio` with small windows.
- **circuit_breaker**: opens at threshold; rejects while open; transitions to half-open after timeout; probe success closes; probe failure reopens.
- **llm_client**: httpx errors mapped to correct `LLMError` subclasses (mock `httpx` transport / `respx` or monkeypatch); 400/401 not retried; connection error retried up to `max_retries`; error logs emitted. Async tests via `pytest-asyncio`.
- **agent**: tool exception is caught and loop continues (mock LLM + mock tool that raises); policy violation fed back without termination; 3 consecutive errors terminates with summary.

Coverage target and CI are Phase 3 concerns; this phase ensures every new module ships with direct unit tests. New test dependencies (`pytest`, `pytest-asyncio`) are added to `requirements.txt` per the task list.

## Dependencies Added

Appended to `requirements.txt` (Req 1.x / 4.1 / 7.1 / 10.1):

```
structlog>=23.0.0
tenacity>=8.0.0
python-dotenv>=1.0.0
pydantic-settings>=2.0
pytest>=7.0.0
pytest-asyncio>=0.21
```

`pydantic>=2.0` and `httpx>=0.27.0` already present.
