# Implementation Plan

Each task is self-contained, references the requirements it satisfies, and ends with a runnable verification step. Execute top to bottom. A task is "done" only when its verification passes and it is checked off.

- [x] 1. Add Phase 1 dependencies and install
  - Append `structlog>=23.0.0`, `tenacity>=8.0.0`, `python-dotenv>=1.0.0`, `pydantic-settings>=2.0`, `pytest>=7.0.0`, `pytest-asyncio>=0.21` to `requirements.txt` (keep existing `pydantic`/`httpx`)
  - Install into the project venv: `venv/bin/pip install -r requirements.txt`
  - _Verify:_ `venv/bin/python -c "import structlog, tenacity, pydantic_settings, pytest"` exits 0
  - _Requirements: 1.1, 4.1, 7.1, 10.1_

- [x] 2. Implement custom exception hierarchy
  - Create `quarr/core/exceptions.py` with `QuarrError` base (`message`, `error_code`, `context`, `cause`, `to_dict()`)
  - Add `LLMError` + `LLMConnectionError`, `LLMTimeoutError`, `LLMRateLimitError`, `LLMResponseError`
  - Add `ToolError` + `ToolNotFoundError`, `ToolExecutionError`, `ToolTimeoutError`, `ToolOutputParseError`
  - Add `ValidationError` + `ConfigValidationError`, `TargetValidationError`, `ArgumentValidationError`
  - Add `PolicyViolationError(QuarrError)`
  - _Verify:_ write `tests/test_exceptions.py` asserting inheritance and `to_dict()` keys; run `venv/bin/pytest tests/test_exceptions.py -v`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

- [x] 3. Wire PolicyViolation to the new hierarchy without breaking imports
  - In `quarr/core/policy.py`, import `PolicyViolationError` from `exceptions` and set `PolicyViolation = PolicyViolationError` (alias) so existing `from quarr.core.policy import PolicyViolation` and `except PolicyViolation` in `agent.py` still work
  - Update `raise PolicyViolation(...)` sites to pass a `context` dict where useful
  - _Verify:_ `venv/bin/python -c "from quarr.core.policy import PolicyViolation; from quarr.core.exceptions import QuarrError; assert issubclass(PolicyViolation, QuarrError)"`
  - _Requirements: 1.5_

- [x] 4. Implement structured logging module
  - Create `quarr/core/logging.py` with `configure_logging(level, fmt, redact_keys)`, `get_logger(name)`, `bind_correlation_id(cid=None)`, `get_correlation_id()`
  - Build structlog processor chain: contextvars merge, ISO-8601 UTC timestamp, level, logger name, redaction processor, then Console or JSON renderer
  - Route stdlib root logger through structlog `ProcessorFormatter` so existing `logging.getLogger("quarr.*")` calls inherit formatting
  - Implement `_redaction_processor` that recursively masks values for keys in `redact_keys` (default: api_key, authorization, password, secret, token, credential)
  - _Verify:_ `tests/test_logging.py` — redaction masks nested secret; correlation ID appears in two loggers; `configure_logging(fmt="json")` produces parseable JSON. Run `venv/bin/pytest tests/test_logging.py -v`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 5.7_

- [x] 5. Implement configuration management
  - Create `quarr/core/config.py` with `Settings(BaseSettings)` (env_prefix `QUARR_`, `.env` file, legacy aliases for OPENAI/OLLAMA/threat-intel keys) per design
  - Add all typed fields: backend, keys, models, timeouts, retries, rate limit, circuit breaker, backoff, logging, audit
  - Implement `validate_runtime()` raising `ConfigValidationError(field=..., context={expected_type})`; resolve `auto` backend; range-check numerics; require OpenAI key when backend resolves to openai
  - Implement `redacted_summary()` masking all `*_api_key` fields
  - _Verify:_ `tests/test_config.py` — defaults load; openai backend + empty key raises `ConfigValidationError`; out-of-range value raises; `redacted_summary()` masks keys; `QUARR_LOG_LEVEL` and legacy `OPENAI_API_KEY` both parse via `monkeypatch.setenv`. Run `venv/bin/pytest tests/test_config.py -v`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8_

- [x] 6. Update .env.example documentation
  - Rewrite `.env.example` grouped by category (LLM Backend, Retry/Resilience, Logging, Audit, Threat Intelligence), marking required vs optional, with defaults as comments
  - Include `QUARR_LOG_LEVEL`, `QUARR_LOG_FORMAT`, `QUARR_AUDIT_LOG_PATH`, `QUARR_LLM_TIMEOUT`, `QUARR_LLM_MAX_RETRIES`, `QUARR_RATE_LIMIT_TPM`, `QUARR_CIRCUIT_BREAKER_THRESHOLD`, `QUARR_CIRCUIT_BREAKER_TIMEOUT`
  - _Verify:_ `grep` confirms each required variable name is present in `.env.example`
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7_

- [x] 7. Implement audit logger
  - Create `quarr/core/audit.py` with `AuditLogger(path, rotate_max_bytes, rotate_backups)`, `record_execution(...) -> seq`, `record_result(seq, success, duration_ms, result_summary)`
  - Write newline-delimited JSON to a dedicated `RotatingFileHandler`; seed sequence from existing file tail on init; compute SHA-256 over entry (excluding hash field); apply redaction to arguments and result_summary
  - _Verify:_ `tests/test_audit.py` — sequence increments and persists across re-init; each entry has valid sha256; secrets redacted; rotation occurs with tiny `max_bytes`. Run `venv/bin/pytest tests/test_audit.py -v`
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

- [x] 8. Implement token-bucket rate limiter
  - Create `quarr/core/rate_limiter.py` with thread-safe `TokenBucket(rate_per_minute, burst)` and `async acquire(max_wait=30.0)`
  - Refill by elapsed time; consume token if available; wait if not; raise `LLMRateLimitError` when required wait > `max_wait`; log DEBUG token count/wait
  - _Verify:_ `tests/test_rate_limiter.py` — burst passes immediately; over-limit waits then proceeds; wait>max raises `LLMRateLimitError`. Run `venv/bin/pytest tests/test_rate_limiter.py -v`
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

- [x] 9. Implement circuit breaker
  - Create `quarr/core/circuit_breaker.py` with `CircuitState` enum and `CircuitBreaker(threshold, window, reset_timeout)` exposing `async call(coro_fn, *a, **kw)`
  - Implement CLOSED/OPEN/HALF_OPEN transitions; reject fast when OPEN with `LLMConnectionError("circuit open")`; single probe in HALF_OPEN; log WARNING on transitions with from/to/reason
  - _Verify:_ `tests/test_circuit_breaker.py` — opens at threshold; rejects while open; half-open after timeout; probe success closes, probe failure reopens. Run `venv/bin/pytest tests/test_circuit_breaker.py -v`
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7, 12.8_

- [x] 10. Add error mapping + retry to LLM client
  - In `quarr/core/llm_client.py`, add a shared `_do_request()` that maps httpx errors to `LLMConnectionError`/`LLMTimeoutError`/`LLMRateLimitError`/`LLMResponseError` with the context specified in design; replace bare `raise_for_status()` in both `OpenAIClient` and `OllamaClient`
  - Log ERROR before raising, including request context (backend, model, message count)
  - Build a `tenacity` retry (exponential backoff from Settings, retry only on connection/timeout, respect retry-after on 429, never retry 400/401, `before_sleep` WARNING log, `reraise=True`) and apply around the request path
  - Add INFO log on request (backend, model, message count) and DEBUG on response (status, tool_call count)
  - _Verify:_ `tests/test_llm_client.py` (async, mocked transport) — 429→`LLMRateLimitError`; 500→`LLMResponseError`; connect error→`LLMConnectionError` retried up to max; 401 not retried. Run `venv/bin/pytest tests/test_llm_client.py -v`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 5.1, 5.2, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8_

- [x] 11. Compose rate limiter + circuit breaker into the client call path
  - Wire `TokenBucket.acquire()` → `CircuitBreaker.call()` → retried `_do_request()` inside `chat()` (or a wrapper in `create_llm_client`), constructed from `Settings`
  - Ensure `create_llm_client` accepts/reads `Settings` for timeout/model/backend resolution while preserving current signature defaults
  - _Verify:_ `tests/test_llm_client.py` extended — repeated connection failures open the breaker and subsequent call is rejected fast. Run `venv/bin/pytest tests/test_llm_client.py -v`
  - _Requirements: 11.4, 12.2, 12.3_

- [x] 12. Harden the agent loop
  - In `quarr/core/agent.py`, wrap tool-handler dispatch in try/except for `PolicyViolationError` (WARNING, feed back to LLM), `ToolError` (ERROR, record failed `ToolExecution`, feed back), and generic `Exception` (ERROR with correlation ID + `exc_info`, feed back)
  - Track `consecutive_errors`; reset on success; terminate loop at 3 with a data summary (Req 3.4)
  - Emit INFO logs for tool start/complete with duration ms (Req 5.3, 5.4) and DEBUG in policy authorize (Req 5.5); WARNING on policy violation (Req 5.6)
  - Record each execution to the `AuditLogger` (start → `record_execution`, end → `record_result`)
  - Add optional `duration_ms`/`error` fields to `ToolExecution` in `models.py` if needed
  - _Verify:_ `tests/test_agent.py` (mock LLM + mock tools) — raising tool caught, loop continues; policy violation fed back without terminating; 3 consecutive errors terminates with summary. Run `venv/bin/pytest tests/test_agent.py -v`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.6, 3.7, 5.3, 5.4, 5.5, 5.6_

- [x] 13. Wire startup sequence in main.py
  - Replace `logging.basicConfig` and manual `load_env` with: `Settings()` → `configure_logging(settings.log_level, settings.log_format)` → `settings.validate_runtime()` (on `ConfigValidationError`: log CRITICAL, `sys.exit(1)`) → INFO log `config_loaded` with `redacted_summary()` → construct `AuditLogger` → construct `QuarrAgent`
  - Bind a fresh correlation ID per agent turn in the REPL loop
  - Wrap agent construction so unrecoverable init errors log CRITICAL and exit non-zero (Req 3.5)
  - _Verify:_ run `venv/bin/python main.py` with no OpenAI key + `QUARR_LLM_BACKEND=openai` set → exits code 1 with CRITICAL log; with valid Ollama default it reaches the engagement prompt (send EOF to exit). Confirm `config_loaded` log shows masked keys
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 3.5_

- [x] 14. Full Phase 1 verification pass
  - Run the whole suite: `venv/bin/pytest tests/ -v`
  - Smoke import check: `venv/bin/python -c "import quarr.core.exceptions, quarr.core.logging, quarr.core.config, quarr.core.audit, quarr.core.rate_limiter, quarr.core.circuit_breaker"`
  - Confirm no regression in existing `tests/test_quarr.py`
  - Update `TASKS.md` Phase 1 rows to ✅ and the progress table
  - _Verify:_ full pytest run green; `TASKS.md` reflects completion
  - _Requirements: all Phase 1 requirements_
