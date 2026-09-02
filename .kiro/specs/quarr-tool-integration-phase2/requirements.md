# Requirements Document

## Introduction

This document specifies the requirements for **Phase 2: Real Tool Integration** of the QUARR Agent. Phase 1 established the foundation (exceptions, logging, config, resilience). Phase 2 replaces ad-hoc, string-built shell commands in `quarr/tools/registry.py` with a structured, secure, and testable tool-integration layer.

The current registry executes tools by building command strings and calling `subprocess.run(shlex.split(...))`. Phase 2 introduces a reusable `ToolIntegration` base class, a hardened subprocess executor, tool availability detection, and dedicated output parsers, then implements concrete integrations for network scanners (Nmap, Nikto, Masscan, Nuclei), web application tools (SQLMap, Gobuster/Dirsearch, WhatWeb, SSLScan), and credential tools (Hydra, Hashcat, John).

This phase depends on Phase 1 exceptions (`ToolError` and subclasses) and the audit/logging infrastructure.

## Glossary

- **Tool_Integration**: A class encapsulating command construction, execution, and output parsing for a single external security tool
- **Tool_Executor**: The hardened component that runs external processes with argument-list execution, timeout, and output capture
- **Tool_Checker**: The component that detects whether an external tool binary is installed and available on PATH
- **Output_Parser**: A component that converts raw tool output (text/XML/JSON) into structured domain models (`Host`, `Service`, `Finding`, `Observation`)
- **Argument_Vector**: A list of command arguments passed to the executor without shell interpretation
- **Tool_Registry**: The existing catalog (`quarr/tools/registry.py`) mapping tool names to handlers and metadata

## Requirements

### Requirement 1: Base Tool Integration Interface

**User Story:** As a developer, I want a common base class for all tool integrations, so that every tool follows the same lifecycle and I can add new tools consistently.

#### Acceptance Criteria

1. THE Tool_Integration SHALL define an abstract base class `ToolIntegration` in `quarr/tools/integrations/base.py`
2. THE ToolIntegration SHALL define abstract methods: `build_command(self, **kwargs) -> list[str]`, `parse_output(self, raw: str) -> dict`, and a class attribute `binary_name: str`
3. THE ToolIntegration SHALL provide a concrete `run(self, **kwargs) -> ToolResult` method that: checks availability, builds the argument vector, executes via Tool_Executor, and parses output
4. THE ToolIntegration SHALL define a `ToolResult` dataclass containing `tool_name`, `success`, `raw_output`, `parsed`, `duration_ms`, and optional `error`
5. WHEN the tool binary is not available, THE ToolIntegration SHALL raise `ToolNotFoundError` with the binary name
6. WHEN command construction receives invalid arguments, THE ToolIntegration SHALL raise `ArgumentValidationError`
7. THE ToolIntegration SHALL declare metadata: `name`, `category`, `risk_level`, `default_timeout`, and `requires_scope`

### Requirement 2: Secure Subprocess Executor

**User Story:** As a security engineer, I want all external tools executed without shell interpretation, so that user- or LLM-supplied values cannot inject arbitrary commands.

#### Acceptance Criteria

1. THE Tool_Executor SHALL execute commands using an argument vector (list) with `shell=False`
2. THE Tool_Executor SHALL NEVER pass concatenated strings to a shell interpreter
3. THE Tool_Executor SHALL enforce a configurable timeout and raise `ToolTimeoutError` when exceeded
4. WHEN the binary is not found, THE Tool_Executor SHALL raise `ToolNotFoundError`
5. WHEN the process exits with a non-zero status that indicates failure, THE Tool_Executor SHALL raise `ToolExecutionError` with exit code and captured stderr
6. THE Tool_Executor SHALL capture stdout and stderr separately and return them with the exit code and duration
7. THE Tool_Executor SHALL reject argument vectors containing shell metacharacters in positions that are not quoted values, validating each argument against an allowlist pattern
8. THE Tool_Executor SHALL support an optional working directory and environment overrides without leaking the parent process secrets

### Requirement 3: Tool Availability Checker

**User Story:** As an operator, I want the agent to know which tools are installed, so that it does not attempt to run missing tools and can report capability gaps.

#### Acceptance Criteria

1. THE Tool_Checker SHALL detect tool availability by resolving the binary on PATH (e.g., `shutil.which`)
2. THE Tool_Checker SHALL cache availability results for the process lifetime
3. THE Tool_Checker SHALL provide `is_available(binary_name) -> bool` and `check_all(integrations) -> dict[str, bool]`
4. WHEN a tool is unavailable, THE Tool_Checker SHALL log at WARNING level with the binary name
5. THE Tool_Checker SHALL optionally capture the tool version string when available
6. THE Tool_Checker SHALL expose a summary suitable for a startup capability report

### Requirement 4: Output Parsers

**User Story:** As an analyst, I want tool outputs converted into structured data, so that findings and services populate the agent state accurately instead of raw text.

#### Acceptance Criteria

1. THE Output_Parser SHALL provide parser functions/classes under `quarr/tools/parsers/`
2. THE Nmap parser SHALL parse XML output (`-oX -`) into `Host` and `Service` models
3. THE Nikto parser SHALL parse JSON/text output into `Finding`/`Observation` records with severity
4. THE Nuclei parser SHALL parse JSONL output into `Finding` records including template ID, severity, and matched URL
5. WHEN parser input is malformed or empty, THE Output_Parser SHALL raise `ToolOutputParseError` with context rather than crashing
6. THE Output_Parser SHALL be pure functions of their input (no side effects) to enable unit testing with fixtures
7. THE parsers SHALL preserve raw output for evidence capture even after structured extraction

### Requirement 5: Network Scanning Integrations

**User Story:** As a penetration tester, I want real Nmap, Nikto, Masscan, and Nuclei integrations, so that scans produce genuine, parseable results.

#### Acceptance Criteria

1. THE system SHALL implement `NmapIntegration` in `quarr/tools/integrations/nmap.py` producing XML output and parsing it to hosts/services
2. THE system SHALL implement `NiktoIntegration` in `quarr/tools/integrations/nikto.py` for web vulnerability scanning
3. THE system SHALL implement `MasscanIntegration` in `quarr/tools/integrations/masscan.py` for fast port scanning
4. THE system SHALL implement `NucleiIntegration` in `quarr/tools/integrations/nuclei.py` producing JSONL output
5. WHEN a network integration runs, THE integration SHALL validate the target against the Phase 4 target validator (or the existing `_validate_target` until Phase 4 lands)
6. THE network integrations SHALL apply per-tool default timeouts appropriate to scan intensity
7. THE network integrations SHALL surface parsed hosts/services/findings so the agent can merge them into `PentestState`

### Requirement 6: Web Application Integrations

**User Story:** As a web application tester, I want real SQLMap, directory brute-force, WhatWeb, and SSLScan integrations, so that web assessments are accurate.

#### Acceptance Criteria

1. THE system SHALL implement `SqlmapIntegration` in `quarr/tools/integrations/sqlmap.py` with batch/non-interactive flags
2. THE system SHALL implement a directory brute-force integration (`DirsearchIntegration` or `GobusterIntegration`) in `quarr/tools/integrations/dirsearch.py`
3. THE system SHALL implement `WhatWebIntegration` in `quarr/tools/integrations/whatweb.py` for fingerprinting
4. THE system SHALL implement `SSLScanIntegration` in `quarr/tools/integrations/sslscan.py` for TLS analysis
5. WHEN a web integration receives a URL, THE integration SHALL normalize it via the URL validator ensuring a scheme is present
6. THE SQLMap integration SHALL never run in interactive mode and SHALL cap risk/level parameters to safe defaults unless explicitly overridden
7. THE web integrations SHALL parse tool output into `Finding`/`Observation` records where applicable

### Requirement 7: Credential and Password Integrations

**User Story:** As a red teamer, I want Hydra, Hashcat, and John integrations, so that credential testing is performed by real tools within scope.

#### Acceptance Criteria

1. THE system SHALL implement `HydraIntegration` in `quarr/tools/integrations/hydra.py` for online brute force
2. THE system SHALL implement `HashcatIntegration` in `quarr/tools/integrations/hashcat.py` for password cracking
3. THE system SHALL implement `JohnIntegration` in `quarr/tools/integrations/john.py` for password cracking
4. THE credential integrations SHALL be classified as HIGH or CRITICAL risk in their metadata
5. WHEN a credential integration is invoked, THE integration SHALL require an in-scope target and SHALL be subject to policy authorization
6. THE credential integrations SHALL never log discovered credentials in plaintext; results SHALL be redacted in logs and summaries
7. THE credential integrations SHALL accept wordlist/hashfile paths validated against path traversal (allowlisted directories) before execution

### Requirement 8: Registry Integration and Backward Compatibility

**User Story:** As a maintainer, I want the new integrations wired into the existing registry, so that the agent uses real tools without breaking current tool names or handler signatures.

#### Acceptance Criteria

1. THE Tool_Registry SHALL route existing tool names (e.g., `network_discovery`, `service_enumeration`, `sqli_scan`) to the corresponding new integrations
2. THE registry handlers SHALL preserve their current callable signature so `agent.py` dispatch remains unchanged
3. WHEN an integration is unavailable, THE registry handler SHALL return a clear "tool not installed" message instead of raising an unhandled exception
4. THE registry SHALL retain `ToolMeta` metadata (name, category, risk, requires_scope, timeout) for each migrated tool
5. THE migration SHALL keep the existing `TOOL_REGISTRY` count at or above its current size (90+ tools) with no removed tool names
6. THE parsed structured results SHALL be returned to the agent in addition to a human-readable summary string
