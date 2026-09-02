# Implementation Plan

Execute top to bottom. Depends on Phase 1 exceptions/logging/config and Phase 2 executor. Each task ends with a runnable verification.

- [x] 1. Create validators package with target validation
  - Create `quarr/core/validators/__init__.py` and `target.py` with `normalize(target, allow_private=True)` and `is_valid`, using `ipaddress`; reject metachars/whitespace, loopback/link-local/multicast (unless allowed); extract host from URLs
  - Re-export `_validate_target`/`_validate_domain` from `registry.py` as thin wrappers calling `normalize` (preserve valid-input behavior)
  - _Verify:_ `tests/test_validator_target.py` — valid IPv4/IPv6/CIDR/hostname normalize; metachar/whitespace and loopback raise `TargetValidationError`. Run `venv/bin/pytest tests/test_validator_target.py -v`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

- [x] 2. Command sanitization
  - Create `quarr/core/validators/command.py` with `validate_arg` and `validate_argv` (allowlist regex + dangerous-char set)
  - Wire Phase 2 `SecureExecutor` to call `validate_argv` (single source of truth)
  - _Verify:_ `tests/test_validator_command.py` — table of injection payloads (`;`, `|`, `$()`, backticks, `>`, newline) all raise `ArgumentValidationError`; flags/IPs/URLs pass. Run `venv/bin/pytest tests/test_validator_command.py -v`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

- [x] 3. Path traversal protection
  - Create `quarr/core/validators/path.py` with `validate_within(path, base)` (realpath + commonpath) and `safe_join(base, *parts)`; reject `..` escapes and out-of-base symlinks
  - _Verify:_ `tests/test_validator_path.py` (uses `tmp_path`) — in-base accepted; `..` escape and symlink-out raise `ValidationError`. Run `venv/bin/pytest tests/test_validator_path.py -v`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

- [x] 4. File type validation
  - Create `quarr/core/validators/file.py` with `validate_file(path, kind, base, max_bytes)` composing path validation + extension allowlist + size + optional signature check
  - _Verify:_ `tests/test_validator_file.py` — allowed extension passes; disallowed and oversize raise `ValidationError`. Run `venv/bin/pytest tests/test_validator_file.py -v`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

- [x] 5. Secrets manager (detection + redaction)
  - Create `quarr/core/secrets.py` with `PATTERNS`, `Secret` dataclass, `detect(text)`, `redact(text)`, and canonical `REDACTION_KEYS`
  - Point the Phase 1 logging redaction processor and `AuditLogger` at `REDACTION_KEYS`; apply `redact` to tool result summaries before logging
  - _Verify:_ `tests/test_secrets.py` — detect positives (AWS/openai/bearer/private key/password kv) and negatives; `redact` masks all; seeded secret absent from captured log output. Run `venv/bin/pytest tests/test_secrets.py -v`
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

- [x] 6. External secret provider support
  - In `quarr/core/config.py`, add `SecretProvider` protocol, `EnvSecretProvider`, optional lazy-imported `VaultSecretProvider`, and `build_secret_provider(settings)`; add `secret_provider` + vault settings
  - Resolve API keys through the provider at startup; unreachable configured provider → `ConfigValidationError`
  - _Verify:_ `tests/test_secret_provider.py` — env provider returns values; default is env; misconfigured vault (mocked) raises `ConfigValidationError`. Run `venv/bin/pytest tests/test_secret_provider.py -v`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [x] 7. Permission system
  - Create `quarr/core/permissions.py` with roles, `RISK_MIN_ROLE`, and `check(role, risk)` raising `PolicyViolationError` when insufficient
  - _Verify:_ `tests/test_permissions.py` — allow/deny matrix across roles × risk levels. Run `venv/bin/pytest tests/test_permissions.py -v`
  - _Requirements: 8.1, 8.2, 8.3, 8.5, 8.6_

- [x] 8. Scope limiter
  - Create `quarr/core/scope.py` with `ScopeLimiter(max_targets, max_rate_per_min).check(target, engagement, session)` using normalized targets, distinct-target cap, and per-engagement rate window
  - _Verify:_ `tests/test_scope.py` — out-of-scope, exceeded target cap, and exceeded rate each raise `PolicyViolationError`. Run `venv/bin/pytest tests/test_scope.py -v`
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

- [x] 9. Approval workflow
  - Create `quarr/core/approval.py` with `ApprovalWorkflow(auto_approve, prompt_fn).gate(tool_name, target, meta)`; require approval for HIGH/CRITICAL; deny/timeout rejects; record decisions in audit
  - _Verify:_ `tests/test_approval.py` — LOW/MEDIUM no prompt; HIGH/CRITICAL prompt via injected `prompt_fn`; denial raises `PolicyViolationError` and audits; `auto_approve` bypasses. Run `venv/bin/pytest tests/test_approval.py -v`
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

- [x] 10. Integrate into PolicyEngine authorization pipeline
  - Extend `PolicyEngine.authorize` (keyword-only `role`, `session` with defaults) to run Permission → Scope → existing scope checks → Approval in order, using `TargetValidator.normalize`
  - Wire `session_role`, `auto_approve_dangerous`, scope limits from `Settings`; pass through from `agent.py`/`main.py`
  - _Verify:_ `tests/test_policy_integration.py` — full pipeline order enforced; existing `tests/test_quarr.py::test_policy` stays green. Run `venv/bin/pytest tests/test_policy_integration.py tests/test_quarr.py -v`
  - _Requirements: 8.4, 9.6, 10.7_

- [x] 11. Phase 4 verification pass
  - Run full suite `venv/bin/pytest tests/ -v`
  - Import smoke: `venv/bin/python -c "import quarr.core.validators.target, quarr.core.validators.command, quarr.core.validators.path, quarr.core.validators.file, quarr.core.secrets, quarr.core.permissions, quarr.core.scope, quarr.core.approval"`
  - Add `hvac>=2.0.0` (optional) to `requirements.txt`; update `.env.example` with new `QUARR_SECRET_PROVIDER`, scope, role, approval settings
  - Update `TASKS.md` Phase 4 rows to ✅ and progress table
  - _Verify:_ full pytest green; imports succeed; TASKS.md updated
  - _Requirements: all Phase 4 requirements_
