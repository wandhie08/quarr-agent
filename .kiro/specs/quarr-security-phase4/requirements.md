# Requirements Document

## Introduction

This document specifies the requirements for **Phase 4: Security Hardening** of the QUARR Agent. Because QUARR executes real offensive security tools driven by LLM output, it must rigorously validate all inputs, protect secrets, and enforce access control. Phase 4 consolidates the scattered validation helpers (`_validate_target`, `_validate_url`, `_validate_domain` in `registry.py`) into a dedicated `quarr/core/validators/` package, adds secrets detection/redaction, and introduces a permission, scope, and approval system layered on top of the existing `PolicyEngine`.

This phase depends on Phase 1 exceptions (`ValidationError` subtree, `PolicyViolationError`) and logging redaction, and Phase 2's executor (which already blocks shell metacharacters).

## Glossary

- **Target_Validator**: Validates and normalizes IP/CIDR/domain/hostname targets
- **Command_Validator**: Sanitizes and validates command arguments against injection
- **Path_Validator**: Prevents path traversal and confines file access to allowlisted directories
- **File_Validator**: Validates file types/extensions for evidence and wordlists
- **Secrets_Manager**: Detects and redacts secrets in outputs and integrates external secret stores
- **Permission_System**: Role-based access control governing which tools a role may run
- **Scope_Limiter**: Enforces engagement scope beyond the base policy (rate, target caps)
- **Approval_Workflow**: Requires explicit confirmation before running dangerous tools
- **Policy_Engine**: Existing authorization layer (`quarr/core/policy.py`) that this phase extends

## Requirements

### Requirement 1: Target Validation

**User Story:** As a security engineer, I want strict target validation, so that malformed or malicious target strings cannot cause injection or out-of-scope actions.

#### Acceptance Criteria

1. THE Target_Validator SHALL be implemented in `quarr/core/validators/target.py`
2. THE Target_Validator SHALL validate and normalize IPv4, IPv6, CIDR, and hostnames
3. WHEN a target contains shell metacharacters or whitespace, THE Target_Validator SHALL raise `TargetValidationError`
4. THE Target_Validator SHALL reject targets that resolve to loopback, link-local, or multicast ranges unless explicitly allowed by configuration
5. THE Target_Validator SHALL normalize URLs to extract host, stripping scheme, path, query, and fragment for scope checks
6. THE Target_Validator SHALL return a canonical normalized form used consistently by the Policy_Engine and integrations
7. THE Target_Validator SHALL replace the ad-hoc `_validate_target`/`_validate_domain` helpers while preserving their accepted-input behavior for valid inputs

### Requirement 2: Command Sanitization

**User Story:** As a security engineer, I want command arguments sanitized, so that no LLM- or user-supplied value can inject additional commands.

#### Acceptance Criteria

1. THE Command_Validator SHALL be implemented in `quarr/core/validators/command.py`
2. THE Command_Validator SHALL validate individual argument-vector elements against an allowlist character pattern
3. WHEN an argument contains shell metacharacters (`;`, `|`, `&`, `$`, backtick, `>`, `<`, newline), THE Command_Validator SHALL raise `ArgumentValidationError`
4. THE Command_Validator SHALL provide a helper to validate a full argument vector used by the Phase 2 `SecureExecutor`
5. THE Command_Validator SHALL never reconstruct a shell string; it operates on lists only
6. THE Command_Validator SHALL allow flags (e.g., `-sV`, `--batch`) and typical values (IPs, URLs without dangerous chars, numeric ranges)
7. THE Command_Validator SHALL be covered by unit tests including known injection payloads that must all be rejected

### Requirement 3: Path Traversal Protection

**User Story:** As a security engineer, I want path traversal protection, so that file operations cannot escape allowlisted directories.

#### Acceptance Criteria

1. THE Path_Validator SHALL be implemented in `quarr/core/validators/path.py`
2. THE Path_Validator SHALL resolve paths to absolute canonical form and verify they are contained within an allowlisted base directory
3. WHEN a path contains `..` traversal that escapes the base directory, THE Path_Validator SHALL raise `ValidationError`
4. THE Path_Validator SHALL reject symlinks that point outside the allowlisted base directory
5. THE Path_Validator SHALL provide `validate_within(path, base)` and `safe_join(base, *parts)` helpers
6. THE Path_Validator SHALL be used by evidence storage, wordlist/hashfile access, and report export paths
7. THE allowlisted base directories SHALL be configurable (engagement dir, `/usr/share/wordlists`, report output dir)

### Requirement 4: File Type Validation

**User Story:** As a security engineer, I want file type validation, so that uploaded or referenced files are of expected types before use.

#### Acceptance Criteria

1. THE File_Validator SHALL be implemented in `quarr/core/validators/file.py`
2. THE File_Validator SHALL validate file extensions against an allowlist per use case (evidence, wordlist, hashfile, report)
3. THE File_Validator SHALL optionally verify content signature/MIME for known types
4. WHEN a file exceeds a configurable maximum size, THE File_Validator SHALL raise `ValidationError`
5. WHEN a file has a disallowed extension or type, THE File_Validator SHALL raise `ValidationError`
6. THE File_Validator SHALL compose with the Path_Validator so both location and type are checked

### Requirement 5: Secrets Never Logged

**User Story:** As a compliance officer, I want secrets never written to logs, so that credentials and API keys are not leaked through log files.

#### Acceptance Criteria

1. THE system SHALL route all log output through the Phase 1 redaction processor so keys matching secret patterns are masked
2. THE Secrets_Manager SHALL define the canonical redaction key list and pattern set used by logging, audit, and reporting
3. WHEN a tool result summary or evidence content is stored, THE system SHALL apply redaction to detected credential patterns before writing to logs (raw evidence files remain per evidence policy)
4. THE system SHALL redact API keys (`sk-...`, bearer tokens), passwords, and private keys in any log or console output
5. THE redaction SHALL be verified by tests asserting that seeded secrets never appear in captured log output

### Requirement 6: Secrets Detection in Outputs

**User Story:** As an operator, I want secrets detected in tool outputs, so that leaked credentials are flagged and handled carefully.

#### Acceptance Criteria

1. THE Secrets_Manager SHALL be implemented in `quarr/core/secrets.py`
2. THE Secrets_Manager SHALL provide `detect(text) -> list[Secret]` matching common patterns (AWS keys, bearer tokens, private keys, generic API keys, password fields)
3. THE Secrets_Manager SHALL provide `redact(text) -> str` replacing detected secrets with masked placeholders
4. WHEN secrets are detected in tool output, THE system SHALL log a WARNING (without the secret value) noting the count and type
5. THE Secrets_Manager SHALL return match metadata (type, position range) without exposing the full secret in logs
6. THE detection patterns SHALL be unit-tested against positive and negative samples

### Requirement 7: External Secret Manager Support

**User Story:** As a system administrator, I want optional external secret manager support, so that API keys can be sourced from a vault rather than environment variables.

#### Acceptance Criteria

1. THE Config_Manager SHALL support resolving secrets from an external provider interface defined in `quarr/core/config.py`
2. THE system SHALL define a `SecretProvider` interface with an `EnvSecretProvider` default and an optional `VaultSecretProvider` (HashiCorp Vault)
3. WHEN an external provider is configured, THE Config_Manager SHALL resolve API keys through it at startup, falling back to environment if unavailable
4. THE external provider integration SHALL never write resolved secret values to logs
5. THE provider selection SHALL be configurable via a `QUARR_SECRET_PROVIDER` setting with a safe default of `env`
6. WHEN the configured provider is unreachable, THE Config_Manager SHALL fail startup with a clear `ConfigValidationError` rather than silently using empty secrets

### Requirement 8: Tool Permission System

**User Story:** As a team lead, I want role-based tool permissions, so that only authorized roles can run high-risk tools.

#### Acceptance Criteria

1. THE Permission_System SHALL be implemented in `quarr/core/permissions.py`
2. THE Permission_System SHALL define roles (e.g., `viewer`, `operator`, `admin`) and map each tool's risk level to a minimum required role
3. WHEN a tool is invoked by a role lacking permission, THE Permission_System SHALL raise `PolicyViolationError` with the tool and required role
4. THE Permission_System SHALL integrate with the Policy_Engine authorization path so permission checks occur before execution
5. THE role of the current session SHALL be configurable (default `operator`)
6. THE Permission_System SHALL be covered by tests asserting allow/deny per role and risk level

### Requirement 9: Scope Limitations

**User Story:** As an engagement manager, I want enforceable scope limits, so that the agent cannot exceed authorized targets or intensity.

#### Acceptance Criteria

1. THE Scope_Limiter SHALL be implemented in `quarr/core/scope.py`
2. THE Scope_Limiter SHALL enforce the engagement `allowed_targets`/`excluded_targets` using the Target_Validator normalized form
3. THE Scope_Limiter SHALL enforce a configurable maximum number of distinct targets per engagement
4. THE Scope_Limiter SHALL enforce a configurable maximum tool-execution rate per engagement to limit intensity
5. WHEN a scope limit is exceeded, THE Scope_Limiter SHALL raise `PolicyViolationError` with the limit that was hit
6. THE Scope_Limiter SHALL integrate with the Policy_Engine so limits are checked before execution

### Requirement 10: Approval Workflow for Dangerous Tools

**User Story:** As a security lead, I want dangerous tools to require explicit approval, so that high-impact actions are not taken autonomously.

#### Acceptance Criteria

1. THE Approval_Workflow SHALL be implemented in `quarr/core/approval.py`
2. THE Approval_Workflow SHALL classify tools by risk and require approval for HIGH and CRITICAL risk tools
3. WHEN a dangerous tool is requested, THE Approval_Workflow SHALL pause execution and request explicit confirmation before proceeding
4. WHEN approval is denied or times out, THE Approval_Workflow SHALL reject the execution with a clear message fed back to the agent
5. THE Approval_Workflow SHALL support an auto-approve configuration for non-interactive runs, defaulting to requiring approval
6. THE Approval_Workflow SHALL record each approval decision (approved/denied, tool, target, timestamp) in the audit log
7. THE Approval_Workflow SHALL integrate into the Policy_Engine/agent path so it gates execution of classified tools
