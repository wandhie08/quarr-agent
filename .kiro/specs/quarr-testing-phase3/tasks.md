# Implementation Plan

Execute top to bottom. Each task ends with a runnable verification. Best done after Phase 1 and Phase 2, but the framework/fixtures (tasks 1-2) can be built first.

- [x] 1. Configure test framework, coverage, and lint
  - Add `pytest-cov>=4.0.0`, `ruff>=0.4.0`, `black>=24.0.0` to `requirements.txt`; install with `venv/bin/pip install -r requirements.txt`
  - Add `[tool.pytest.ini_options]` (testpaths, `asyncio_mode="auto"`, markers, addopts), `[tool.coverage.run]`/`[tool.coverage.report]` (`fail_under=60`), `[tool.ruff]`, `[tool.black]` to `pyproject.toml` (create it if absent)
  - _Verify:_ `venv/bin/pytest --co -q` collects tests without config errors; `venv/bin/ruff --version` and `venv/bin/black --version` run
  - _Requirements: 1.1, 1.2, 1.3, 1.5, 5.1, 5.2, 5.5, 5.6, 7.1, 7.2, 7.3_

- [x] 2. Create shared fixtures and test data
  - Create `tests/conftest.py` with fixtures: `sample_engagement`, `populated_state`, `tmp_engagements_dir`, `tmp_audit_path`, `mock_llm` (MockLLM + `tool_call` helper), `fake_post`, `mock_executor`, `load_fixture`
  - Create `tests/fixtures/` with `nmap.xml`, `nuclei.jsonl`, `nikto.json`, `hydra_output.txt`
  - _Verify:_ `tests/test_fixtures_smoke.py` uses each fixture and asserts it loads; run `venv/bin/pytest tests/test_fixtures_smoke.py -v`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [x] 3. Unit tests for LLM client
  - Create `tests/test_llm_client.py` using `fake_post` to cover: success+tool_calls parse; 429→`LLMRateLimitError`; 500→`LLMResponseError`; connect error→`LLMConnectionError` retried up to max; 401 not retried
  - _Verify:_ `venv/bin/pytest tests/test_llm_client.py -v`
  - _Requirements: 3.1, 3.6, 3.7_

- [x] 4. Unit tests for agent
  - Create `tests/test_agent.py` with `mock_llm` + `mock_executor`: tool call updates state; tool exception caught and loop continues; policy violation fed back without terminating; 3 consecutive errors terminate with summary
  - _Verify:_ `venv/bin/pytest tests/test_agent.py -v`
  - _Requirements: 3.2, 3.6, 3.7_

- [x] 5. Unit tests for tools, parsers, knowledge
  - Create `tests/test_tools.py` (one tool per category via `mock_executor`; unavailable tool friendly string), `tests/test_parsers.py` (fixture parse counts + malformed→`ToolOutputParseError`), `tests/test_knowledge.py` (`retrieve_knowledge`, `get_cwe_for_finding` returns CWE-89 for SQLi, `get_cvss_range`)
  - _Verify:_ `venv/bin/pytest tests/test_tools.py tests/test_parsers.py tests/test_knowledge.py -v`
  - _Requirements: 3.3, 3.4, 3.5, 3.6, 3.7_

- [x] 6. Integration tests
  - Create `tests/integration/__init__.py`, `test_tool_chain.py` (integration `run()` with `mock_executor` + real parser), `test_agent_flow.py` (full turn: tool call then final answer, assert state updated), `test_reporter.py` (exec/technical/JSON from `populated_state`)
  - Mark all with `@pytest.mark.integration`
  - _Verify:_ `venv/bin/pytest tests/integration -m integration -v`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

- [x] 7. Migrate/keep smoke test and run coverage
  - Ensure `tests/test_quarr.py` still passes under pytest (or migrate its assertions into the new files without losing coverage)
  - Run `venv/bin/pytest tests/ --cov=quarr --cov-report=term-missing --cov-report=html`
  - _Verify:_ suite green; coverage report generated in `htmlcov/`; coverage meets `fail_under=60` (or adjust target with justification if legitimately lower)
  - _Requirements: 1.4, 1.6, 5.3, 5.4_

- [x] 8. Create CI pipeline
  - Create `.github/workflows/test.yml` running on push/PR: setup Python 3.13 with pip cache, install deps, `ruff check quarr/`, `black --check quarr/`, `pytest tests/ --cov=quarr`, upload `htmlcov/` artifact
  - _Verify:_ `venv/bin/python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/test.yml'))"` parses without error; locally run the same commands the workflow runs and confirm they pass
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

- [x] 9. Phase 3 verification pass
  - Run `venv/bin/pytest tests/ -v`, `venv/bin/ruff check quarr/`, `venv/bin/black --check quarr/`
  - Update `TASKS.md` Phase 3 rows to ✅ and progress table
  - _Verify:_ all three commands succeed; TASKS.md updated
  - _Requirements: all Phase 3 requirements_
