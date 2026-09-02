# Design Document

## Overview

Phase 4 hardens QUARR by consolidating validation into `quarr/core/validators/`, adding a `Secrets_Manager`, and extending the existing `PolicyEngine` with permissions, scope limits, and an approval workflow. It builds directly on the Phase 1 exception tree and redaction, and the Phase 2 `SecureExecutor`.

### Design Principles

- **Single source of truth for validation.** The scattered `_validate_*` helpers in `registry.py` are replaced by the validators package and re-exported for compatibility.
- **Defense in depth.** The executor already rejects metacharacters (Phase 2); Phase 4 adds semantic validation (scope, ranges, private-IP policy) and human-in-the-loop approval for dangerous tools.
- **Policy is the chokepoint.** Permission, scope, and approval checks all funnel through `PolicyEngine.authorize`, which `agent.py` already calls before every tool run.

## Architecture

```
                     ┌───────────────────────────────────┐
                     │            agent.py                 │
                     │  before each tool: policy.authorize │
                     └──────────────────┬──────────────────┘
                                        ▼
                     ┌───────────────────────────────────┐
                     │        policy.py PolicyEngine        │
                     │  authorize():                        │
                     │   1. Permission_System.check         │
                     │   2. Scope_Limiter.check             │
                     │   3. target/scope (existing)         │
                     │   4. Approval_Workflow.gate          │
                     └───┬───────┬────────┬────────┬────────┘
                         ▼       ▼        ▼        ▼
             permissions.py  scope.py  validators/  approval.py
                                        target.py
                                        command.py
                                        path.py
                                        file.py

  secrets.py ──used by──> logging redaction, audit, reporter, evidence
  config.py  ──SecretProvider──> EnvSecretProvider | VaultSecretProvider
```

### Authorization Pipeline (extended `authorize`)

```
authorize(tool_name, args, engagement, *, role, session):
    meta = TOOL_REGISTRY[tool_name]                     # risk level
    Permission_System.check(role, meta.risk)            # → PolicyViolationError
    target = TargetValidator.normalize(args.get("target"))
    Scope_Limiter.check(target, engagement, session)    # count/rate/scope
    #   (existing excluded/allowed checks reuse normalized target)
    if meta.risk in (HIGH, CRITICAL):
        Approval_Workflow.gate(tool_name, target, meta)  # confirm or reject
    return True
```

Backward compatibility: `authorize` keeps its current positional signature; new params (`role`, `session`) are keyword-only with defaults so existing callers/tests keep working.

## Components and Interfaces

### `quarr/core/validators/target.py`

```python
def normalize(target: str, *, allow_private: bool = True) -> str:
    # strip scheme/path/port; classify via ipaddress; reject metachars/whitespace
    # reject loopback/link-local/multicast unless allow_private/config
    # → returns canonical host/CIDR string, else TargetValidationError
def is_valid(target: str) -> bool: ...
```

Reuses `ipaddress` (as `policy.py` does). Replaces `_validate_target`/`_validate_domain`; those names are re-exported from `registry.py` as thin wrappers calling `normalize` to keep Phase 2 imports valid.

### `quarr/core/validators/command.py`

```python
ARG_SAFE = re.compile(r"^[A-Za-z0-9._:/@=,\-\+%]+$")
DANGEROUS = set(";|&$`><\n")
def validate_arg(arg: str) -> str: ...          # ArgumentValidationError on fail
def validate_argv(argv: list[str]) -> list[str]: ...
```

Shared with Phase 2 `SecureExecutor` (executor imports `validate_argv`). Flags and typical values pass; injection payloads fail (Req 2.3, 2.7).

### `quarr/core/validators/path.py`

```python
def validate_within(path: str, base: str) -> str:
    rp = os.path.realpath(path); rb = os.path.realpath(base)
    if os.path.commonpath([rp, rb]) != rb: raise ValidationError(...)
    return rp
def safe_join(base: str, *parts: str) -> str: ...   # then validate_within
```

`realpath` resolves symlinks so links escaping the base are caught (Req 3.4). Base dirs come from config: engagement dir, wordlists dir, reports dir.

### `quarr/core/validators/file.py`

```python
ALLOWED = {"evidence": {".txt",".png",".json",".xml",".log"},
           "wordlist": {".txt",".lst",".dic"},
           "hashfile": {".txt",".hash"},
           "report": {".md",".json",".html",".pdf"}}
def validate_file(path: str, kind: str, base: str, max_bytes: int) -> str:
    p = path_validator.validate_within(path, base)
    # extension allowlist + size + optional signature check
```

### `quarr/core/secrets.py` — Secrets_Manager

```python
PATTERNS = {
  "aws_key": r"AKIA[0-9A-Z]{16}",
  "bearer": r"(?i)bearer\s+[A-Za-z0-9._\-]+",
  "openai": r"sk-[A-Za-z0-9]{20,}",
  "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
  "password_kv": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
  "generic_api": r"(?i)api[_-]?key\s*[:=]\s*\S+",
}
@dataclass
class Secret: kind: str; start: int; end: int
def detect(text: str) -> list[Secret]: ...
def redact(text: str) -> str: ...     # replace spans with ***REDACTED:<kind>***
REDACTION_KEYS = [...]                 # canonical key list used by logging/audit
```

`REDACTION_KEYS` becomes the single source consumed by the Phase 1 logging redaction processor and `AuditLogger` (Req 5.1, 5.2).

### `quarr/core/config.py` — SecretProvider (extends Phase 1 Settings)

```python
class SecretProvider(Protocol):
    def get(self, key: str) -> str | None: ...
class EnvSecretProvider: ...                     # os.environ
class VaultSecretProvider:                        # hvac client, optional dep
    def __init__(self, addr, token, mount): ...
def build_secret_provider(settings) -> SecretProvider: ...
```

`Settings` gains `secret_provider: Literal["env","vault"] = "env"` and vault fields. At startup, API keys resolve through the provider; unreachable configured provider → `ConfigValidationError` (Req 7.6).

### `quarr/core/permissions.py` — Permission_System

```python
ROLE_ORDER = {"viewer":0, "operator":1, "admin":2}
RISK_MIN_ROLE = {RiskLevel.LOW:"viewer", RiskLevel.MEDIUM:"operator",
                 RiskLevel.HIGH:"operator", RiskLevel.CRITICAL:"admin"}
def check(role: str, risk: RiskLevel) -> None:   # PolicyViolationError if insufficient
```

### `quarr/core/scope.py` — Scope_Limiter

```python
class ScopeLimiter:
    def __init__(self, max_targets: int, max_rate_per_min: int): ...
    def check(self, target, engagement, session) -> None:
        # normalized in/excluded checks; distinct-target cap; per-engagement rate
```

Tracks distinct targets and a sliding execution window per session/engagement; exceeding raises `PolicyViolationError` (Req 9.5).

### `quarr/core/approval.py` — Approval_Workflow

```python
class ApprovalWorkflow:
    def __init__(self, auto_approve: bool = False, prompt_fn=input): ...
    def gate(self, tool_name, target, meta) -> None:
        if meta.risk not in (HIGH, CRITICAL): return
        if self.auto_approve: decision = "approved"
        else: decision = self._ask(tool_name, target)   # y/n, timeout → deny
        audit.record_approval(tool_name, target, decision)
        if decision != "approved": raise PolicyViolationError("approval denied")
```

`prompt_fn` is injectable for tests and for the Phase 6 interactive UI. Non-interactive runs set `auto_approve` via config, default requiring approval (Req 10.5).

## Data Models

- New `Secret` dataclass (secrets.py), `CircuitState`-style enums not needed here.
- `Settings` extended with: `secret_provider`, `vault_addr`, `vault_token`, `vault_mount`, `allow_private_targets`, `max_targets`, `max_rate_per_min`, `session_role`, `auto_approve_dangerous`.
- Audit entry gains an `event="approval"` variant `{tool, target, decision, timestamp}`.
- No changes to `PentestState`/`Finding`.

## Error Handling

- Validation failures → `TargetValidationError`/`ArgumentValidationError`/`ValidationError` (Phase 1 tree), surfaced to the agent as recoverable messages by the Phase 1 agent hardening.
- Authorization failures (permission/scope/approval) → `PolicyViolationError`, logged WARNING, fed back to the LLM without terminating the loop.
- Provider unreachable at startup → `ConfigValidationError`, CRITICAL log, exit 1 (reuses Phase 1 startup path).
- Secrets detection never raises on detection; it flags and redacts.

## Testing Strategy

All validators and security components are pure/injectable and unit-tested offline.

- **target**: valid IPv4/IPv6/CIDR/hostname normalize; metachar/whitespace → `TargetValidationError`; loopback rejected unless allowed; URL host extraction.
- **command**: flags/values pass; a table of injection payloads (`; rm -rf`, `$(...)`, backticks, pipes, newlines) all raise `ArgumentValidationError`.
- **path**: `validate_within` accepts in-base; `..` escape and out-of-base symlink raise `ValidationError`; `safe_join`.
- **file**: extension allowlist per kind; oversize raises; disallowed type raises.
- **secrets**: `detect` positive samples (AWS/openai/bearer/private key/password kv) and negatives; `redact` masks all; assert secret value never in redacted output; assert seeded secret absent from captured logs (integrates with Phase 1 logging).
- **config/provider**: `EnvSecretProvider.get`; `build_secret_provider` returns env by default; misconfigured vault → `ConfigValidationError` (vault client mocked).
- **permissions**: allow/deny matrix across roles × risk levels.
- **scope**: in/excluded via normalized target; distinct-target cap; rate cap triggers `PolicyViolationError`.
- **approval**: LOW/MEDIUM pass without prompt; HIGH/CRITICAL prompt via injected `prompt_fn`; denial raises and audits; `auto_approve` bypasses; decisions recorded in audit.
- **policy integration**: extended `authorize` runs permission→scope→approval in order; existing `tests/test_quarr.py::test_policy` stays green.

## Dependencies Added

```
hvac>=2.0.0        # optional, only imported when secret_provider="vault"
```

`hvac` is an optional dependency; the module imports it lazily so the default `env` provider needs no new packages. `ipaddress`, `os`, `re` are stdlib.
