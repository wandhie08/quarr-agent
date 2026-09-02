# Implementation Plan

Execute top to bottom. Tasks 1-6 (CLI) are the required deliverable; tasks 7-10 (Web UI) are optional and may be skipped for MVP. Each task ends with a runnable verification.

- [x] 1. Add rich and create renderer abstraction
  - Add `rich>=13.0.0` to `requirements.txt`; install (`venv/bin/pip install rich`)
  - Create `quarr/cli/__init__.py` and `quarr/cli/render.py` with a `Renderer` protocol, `RichRenderer`, `PlainRenderer`, `SEVERITY_STYLE`, and `get_renderer()` (Rich if importable, else Plain)
  - _Verify:_ `tests/test_cli_render.py` — `get_renderer` returns `PlainRenderer` when rich import is monkeypatched away; `RichRenderer.findings_table` output (record mode) contains a finding title; severity map complete. Run `venv/bin/pytest tests/test_cli_render.py -v`
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 8.3_

- [x] 2. Implement progress indicators
  - Create `quarr/cli/progress.py` with `ProgressReporter` (`async status(message)` matching the agent callback, `spinner(label)` context manager, `plan_progress(total)`)
  - Ensure logs go to stderr and progress to stdout to avoid interleave
  - _Verify:_ `tests/test_cli_progress.py` — `status` is awaitable with correct signature; spinner enters/exits cleanly; plan progress formats "X/N". Run `venv/bin/pytest tests/test_cli_progress.py -v`
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

- [x] 3. Add argparse CLI flags
  - Add `parse_args()` to `main.py` supporting `--interactive`, `--engagement <id>`, `--scope <target>` (append), `--backend`, `--report`, `--help`; load saved session when `--engagement` given; invalid args exit non-zero; no-args keeps current interactive setup
  - _Verify:_ `tests/test_cli_args.py` — flags parse; `--scope` repeatable; invalid arg exits non-zero; `--engagement` triggers `load_state` (mock). Run `venv/bin/pytest tests/test_cli_args.py -v`
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

- [x] 4. Refactor command loop to use the renderer
  - Extract the REPL into `command_loop(agent, renderer)`; route all existing commands (state, findings, scope, history, report, executive, technical, export, save, load, sessions, plan, retest, help, quit) through the renderer; preserve auto-save on quit and after each run
  - Wire the agent `status_callback` to `ProgressReporter.status`
  - _Verify:_ `tests/test_cli_loop.py` — each command dispatches to the right renderer call (mock renderer); auto-save called after run and on quit (mock `save_state`). Run `venv/bin/pytest tests/test_cli_loop.py -v`
  - _Requirements: 1.7, 8.1, 8.2, 8.4, 8.5_

- [x] 5. Implement interactive mode
  - Create `quarr/cli/interactive.py` with `run_interactive(agent, renderer)`: numbered menu (define scope, run discovery, review findings, generate report, back), input validation, contextual help; dangerous actions pass through the Phase 4 approval workflow; preserve all policy/scope checks
  - Launch via `--interactive` flag or an `interactive` command
  - _Verify:_ `tests/test_cli_interactive.py` — invalid choice re-prompts (injected input fn); dangerous action triggers approval (injected prompt); "back" returns to loop. Run `venv/bin/pytest tests/test_cli_interactive.py -v`
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

- [x] 6. CLI verification pass
  - Run `venv/bin/pytest tests/ -v`
  - Manual smoke: `venv/bin/python main.py --help` shows all flags; `echo | venv/bin/python main.py` starts and exits cleanly
  - _Verify:_ tests green; `--help` lists flags; no-arg start works
  - _Requirements: 1.7, 4.6, 8.1, 8.5_

- [ ] 7. (Optional) FastAPI backend
  - Add `fastapi>=0.110.0`, `uvicorn>=0.29.0` to `requirements.txt` (optional section); create `quarr/api/__init__.py` and `app.py` with routes: list engagements, get state (redacted), get findings, POST query (authorization-gated), POST report; Pydantic models; structured 4xx
  - Reuse persistence/agent/reporter; redact via Phase 4 Secrets_Manager
  - _Verify:_ `tests/test_api.py` using FastAPI `TestClient` — list/state/findings return; state has no secret patterns; query gated by authorization (mock agent); invalid input → 4xx; `/openapi.json` served. Run `venv/bin/pytest tests/test_api.py -v`
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

- [ ] 8. (Optional) WebSocket real-time channel
  - Create `quarr/api/websocket.py` with `ConnectionManager` (connect/broadcast/disconnect); wire the agent `status_callback` to broadcast redacted events; handle multiple clients and clean disconnect
  - _Verify:_ `tests/test_websocket.py` using `TestClient` websocket — connect, receive a broadcast event, disconnect cleanly; payload has no secret patterns. Run `venv/bin/pytest tests/test_websocket.py -v`
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [ ] 9. (Optional) Web dashboard
  - Create `quarr/ui/` static dashboard (HTML/JS) consuming the REST API + WS; engagement list, state, findings table, report preview; severity colors matching CLI; insert API content via safe escaping; clear error state when API unavailable
  - _Verify:_ open `quarr/ui/index.html` against a running API (`uvicorn quarr.api.app:app`) and confirm findings render and XSS payload in a finding title is not executed; document the manual smoke result
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

- [x] 10. Phase 6 verification pass
  - Run full suite `venv/bin/pytest tests/ -v`
  - Import smoke: `venv/bin/python -c "import quarr.cli.render, quarr.cli.progress, quarr.cli.interactive"` (and `quarr.api.app` if optional built)
  - Update `TASKS.md` Phase 6 rows to ✅ (CLI required; mark Web UI rows per what was built) and progress table
  - _Verify:_ full pytest green; imports succeed; TASKS.md updated
  - _Requirements: all Phase 6 CLI requirements (Web UI if built)_
