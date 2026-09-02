# Implementation Plan

Execute top to bottom. Each task ends with a runnable verification. Depends on Phase 1 exceptions being in place; if Phase 1 is not done, first create `quarr/core/exceptions.py` with `ToolError` subclasses and `ArgumentValidationError`.

- [x] 1. Create secure subprocess executor
  - Create `quarr/tools/executor.py` with `ExecResult` dataclass and `SecureExecutor.run(argv, timeout, cwd, env)` using `shell=False`
  - Validate each argv element against an allowlist regex; reject shell metacharacters with `ArgumentValidationError`
  - Resolve binary via `shutil.which`; missing → `ToolNotFoundError`; `TimeoutExpired` → `ToolTimeoutError`; use minimal env (PATH only) unless overridden
  - _Verify:_ `tests/test_executor.py` — `echo` happy path; argv with `;`/`|`/`$()` raises `ArgumentValidationError`; missing binary raises `ToolNotFoundError`; `sleep` beyond timeout raises `ToolTimeoutError`. Run `venv/bin/pytest tests/test_executor.py -v`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

- [x] 2. Create tool availability checker
  - Create `quarr/tools/checker.py` with `ToolChecker.is_available`, `version`, `check_all`, `report`, using `shutil.which` and a process-lifetime cache
  - Log WARNING for unavailable tools
  - _Verify:_ `tests/test_checker.py` — monkeypatch `shutil.which` to control availability; assert caching and `check_all` dict. Run `venv/bin/pytest tests/test_checker.py -v`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 3. Create ToolIntegration base class
  - Create `quarr/tools/integrations/__init__.py` and `quarr/tools/integrations/base.py` with `ToolResult` dataclass and abstract `ToolIntegration` (`build_command`, `parse_output`, `binary_name`, metadata, concrete `run`)
  - `run()` checks availability, builds argv, executes, parses, returns `ToolResult`; raises `ToolNotFoundError`/`ArgumentValidationError` per design
  - _Verify:_ `tests/test_integration_base.py` — a dummy subclass runs end-to-end with a mocked executor; unavailable binary raises `ToolNotFoundError`. Run `venv/bin/pytest tests/test_integration_base.py -v`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

- [x] 4. Implement output parsers
  - Create `quarr/tools/parsers/__init__.py`, `nmap.py` (`parse_nmap_xml`), `nikto.py` (`parse_nikto`), `nuclei.py` (`parse_nuclei_jsonl`)
  - Return structured dicts of `Host`/`Service`/`Finding`; raise `ToolOutputParseError` on malformed/empty; keep functions pure
  - Add recorded fixtures under `tests/fixtures/` (nmap.xml, nuclei.jsonl, nikto.json)
  - _Verify:_ `tests/test_parsers_integrations.py` — parse each fixture and assert counts/fields; malformed input raises `ToolOutputParseError`. Run `venv/bin/pytest tests/test_parsers_integrations.py -v`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

- [x] 5. Implement network scanning integrations
  - Create `nmap.py`, `nikto.py`, `masscan.py`, `nuclei.py` under `quarr/tools/integrations/` subclassing `ToolIntegration` with argv per design and appropriate timeouts/risk
  - Validate targets via existing `_validate_target` until Phase 4
  - _Verify:_ `tests/test_network_integrations.py` — mock executor with fixture output; assert `build_command` argv shape and parsed hosts/services/findings. Run `venv/bin/pytest tests/test_network_integrations.py -v`
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

- [x] 6. Implement web application integrations
  - Create `sqlmap.py` (`--batch`, capped level/risk), `dirsearch.py`, `whatweb.py`, `sslscan.py` under integrations
  - Normalize URLs via `_validate_url`; parse to findings/observations where applicable
  - _Verify:_ `tests/test_web_integrations.py` — assert non-interactive flags present; URL normalization; parsed output. Run `venv/bin/pytest tests/test_web_integrations.py -v`
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

- [x] 7. Implement credential/password integrations
  - Create `hydra.py`, `hashcat.py`, `john.py` under integrations with HIGH/CRITICAL risk metadata
  - Validate wordlist/hashfile paths against an allowlist of directories; redact any cracked secret in output summaries and logs
  - _Verify:_ `tests/test_credential_integrations.py` — path outside allowlist raises validation error; cracked-secret fixture is redacted in summary. Run `venv/bin/pytest tests/test_credential_integrations.py -v`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

- [x] 8. Wire integrations into the registry
  - Refactor matching handlers in `quarr/tools/registry.py` to delegate to the new integrations via a `_summarize(ToolResult) -> str` helper, preserving signatures and tool names
  - Return a friendly "tool not installed" string when `ToolNotFoundError` is raised
  - Keep `ToolMeta` metadata; ensure no tool names removed
  - _Verify:_ `venv/bin/pytest tests/test_quarr.py -v` (existing smoke test) stays green including `len(TOOL_REGISTRY) >= 90`; add a case asserting an unavailable tool returns the friendly string. Run `venv/bin/pytest tests/ -v`
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

- [x] 9. Phase 2 verification pass
  - Run full suite `venv/bin/pytest tests/ -v`
  - Import smoke: `venv/bin/python -c "import quarr.tools.executor, quarr.tools.checker, quarr.tools.integrations.base, quarr.tools.integrations.nmap"`
  - Update `TASKS.md` Phase 2 rows to ✅ and progress table
  - _Verify:_ full pytest green; TASKS.md updated
  - _Requirements: all Phase 2 requirements_
