# Requirements Document

## Introduction

This document specifies the requirements for **Phase 3: Testing & Quality** of the QUARR Agent. The project currently has a single smoke test (`tests/test_quarr.py`) that runs plain functions with no fixtures, no async support, and no coverage measurement. Phase 3 establishes a real pytest-based test suite with unit tests, integration tests, shared fixtures, mock LLM and tool responses, code-coverage tracking, and a CI pipeline.

This phase depends on Phase 1 (modules to unit test) and Phase 2 (integrations and parsers to test). It provides the quality gate that later phases rely on.

## Glossary

- **Test_Suite**: The complete collection of automated tests under `tests/`
- **Unit_Test**: A test exercising a single module in isolation using mocks/stubs
- **Integration_Test**: A test exercising multiple components together (e.g., agent + mock LLM + mock tools)
- **Fixture**: A reusable pytest fixture providing test data or configured objects
- **Mock_LLM**: A stand-in LLM client returning scripted responses for deterministic tests
- **Coverage**: The percentage of source lines executed by the test suite, measured by pytest-cov
- **CI_Pipeline**: The automated GitHub Actions workflow that runs the test suite on push/PR

## Requirements

### Requirement 1: Test Framework and Async Support

**User Story:** As a developer, I want a proper pytest setup with async support, so that I can test both synchronous and `async def` code deterministically.

#### Acceptance Criteria

1. THE Test_Suite SHALL use pytest as the test runner
2. THE Test_Suite SHALL configure `pytest-asyncio` for testing `async def` functions
3. THE Test_Suite SHALL define pytest configuration in `pyproject.toml` (or `pytest.ini`) including test paths, async mode, and markers
4. THE Test_Suite SHALL run via `pytest tests/ -v` and complete without requiring external network access or installed security tools
5. THE Test_Suite SHALL define markers to separate `unit` and `integration` tests
6. THE existing `tests/test_quarr.py` smoke checks SHALL remain passing or be migrated into the new structure without loss of coverage

### Requirement 2: Shared Fixtures and Test Data

**User Story:** As a developer, I want reusable fixtures, so that tests share consistent engagement, state, and mock objects without duplication.

#### Acceptance Criteria

1. THE Test_Suite SHALL define shared fixtures in `tests/conftest.py`
2. THE fixtures SHALL include: a sample `Engagement`, a populated `PentestState`, a temporary working directory, and a `Mock_LLM` client
3. THE fixtures SHALL include recorded tool-output samples under `tests/fixtures/` (Nmap XML, Nuclei JSONL, Nikto JSON, and at least one credential-tool output)
4. THE Mock_LLM fixture SHALL allow scripting a sequence of responses including tool calls and final text
5. THE fixtures SHALL provide a temporary audit-log path and temporary engagements directory to avoid polluting the repo
6. THE fixtures SHALL be importable by both unit and integration tests

### Requirement 3: Unit Tests — Core Modules

**User Story:** As a maintainer, I want unit tests for each core module, so that regressions are caught at the smallest scope.

#### Acceptance Criteria

1. THE Test_Suite SHALL include `tests/test_llm_client.py` with mocked HTTP responses covering success, tool calls, and each error mapping
2. THE Test_Suite SHALL include `tests/test_agent.py` testing the agent loop with a Mock_LLM and mocked tools, including error handling and loop termination
3. THE Test_Suite SHALL include `tests/test_tools.py` covering representative tools from each category via mocked executor
4. THE Test_Suite SHALL include `tests/test_parsers.py` covering Nmap/Nikto/Nuclei parsers with fixtures and malformed input
5. THE Test_Suite SHALL include `tests/test_knowledge.py` covering OWASP/CWE/CVSS lookups from `quarr/knowledge/base.py`
6. THE unit tests SHALL mock all external effects (HTTP, subprocess, filesystem writes outside tmp) so they are deterministic and offline
7. WHEN a core module raises a custom exception, THE corresponding unit test SHALL assert the exception type and key context fields

### Requirement 4: Integration Tests

**User Story:** As a maintainer, I want integration tests, so that end-to-end flows across components are validated.

#### Acceptance Criteria

1. THE Test_Suite SHALL include `tests/integration/test_tool_chain.py` exercising an integration's `run()` path with a mocked executor and real parser
2. THE Test_Suite SHALL include `tests/integration/test_agent_flow.py` running a full agent turn with a Mock_LLM that issues a tool call, then a final answer, asserting state is updated
3. THE Test_Suite SHALL include `tests/integration/test_reporter.py` generating executive/technical/JSON reports from a populated state and asserting structure
4. THE integration tests SHALL use fixtures and mocks only; no real security tools or network required
5. WHEN the agent processes a tool call, THE integration test SHALL assert that `PentestState` reflects the parsed results (hosts/services/findings)
6. THE integration tests SHALL be marked with the `integration` marker so they can be run selectively

### Requirement 5: Code Coverage

**User Story:** As a maintainer, I want coverage measurement, so that I can track how much of the codebase is tested and prevent coverage regressions.

#### Acceptance Criteria

1. THE Test_Suite SHALL integrate `pytest-cov` for coverage measurement over the `quarr` package
2. THE coverage configuration SHALL be declared in `pyproject.toml`
3. THE Test_Suite SHALL support generating an HTML coverage report via `pytest --cov=quarr --cov-report=html`
4. THE Test_Suite SHALL support generating a terminal coverage summary via `--cov-report=term-missing`
5. THE coverage configuration SHALL exclude test files, `__pycache__`, and the `venv` directory
6. THE project SHALL define a minimum coverage target (e.g., 60% initial) documented in `pyproject.toml` or CI, failing CI if not met

### Requirement 6: CI/CD Pipeline

**User Story:** As a maintainer, I want tests to run automatically on push and pull requests, so that broken changes are caught before merge.

#### Acceptance Criteria

1. THE CI_Pipeline SHALL be defined in `.github/workflows/test.yml`
2. THE CI_Pipeline SHALL run on `push` and `pull_request` events
3. THE CI_Pipeline SHALL set up Python 3.13, install dependencies from `requirements.txt`, and run `pytest tests/ --cov=quarr`
4. THE CI_Pipeline SHALL run the linter (`ruff check quarr/`) and formatter check (`black --check quarr/`) as separate steps
5. THE CI_Pipeline SHALL fail the build if tests fail, coverage is below the minimum, or lint/format checks fail
6. THE CI_Pipeline SHALL cache pip dependencies to speed up runs
7. THE CI_Pipeline SHALL upload the coverage report as a build artifact

### Requirement 7: Linting and Formatting Configuration

**User Story:** As a developer, I want consistent linting and formatting rules, so that code style is uniform and enforced.

#### Acceptance Criteria

1. THE project SHALL configure `ruff` in `pyproject.toml` with a documented rule set
2. THE project SHALL configure `black` in `pyproject.toml` with line length and target version
3. THE lint configuration SHALL ignore generated and vendored paths (`venv`, `__pycache__`)
4. WHEN `ruff check quarr/` runs, THE command SHALL report violations with rule codes
5. THE formatting SHALL be verifiable non-destructively via `black --check quarr/`
