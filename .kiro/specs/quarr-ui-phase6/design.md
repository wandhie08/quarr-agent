# Design Document

## Overview

Phase 6 improves the user experience without changing agent semantics. The required work is the CLI: extract presentation from `main.py` into a `rich`-based renderer, add progress indicators and a guided interactive mode, and add `argparse` flags. The optional work is a FastAPI backend (`quarr/api/`), a dashboard (`quarr/ui/`), and a WebSocket channel — all thin layers over the existing core modules.

### Design Principles

- **Separate presentation from logic.** A `quarr/cli/` package holds rendering; `main.py` orchestrates. The agent, state, and persistence are untouched.
- **Graceful degradation.** If `rich` is absent, fall back to the current plain `print`. If the API isn't run, the CLI works standalone.
- **Reuse safety.** Interactive mode and the Web API both funnel tool execution through the same `PolicyEngine` path (permissions/scope/approval from Phase 4).
- **No secret leakage.** API responses and WS messages are redacted via the Phase 4 Secrets_Manager.

## Architecture

```
                          main.py
                    ┌────────┴─────────┐
             argparse flags      Command_Loop (REPL, existing commands)
                    │                   │
                    ▼                   ▼
             quarr/cli/                 QuarrAgent (unchanged)
               render.py  ── rich tables/panels/colors
               progress.py ── spinners/progress bars (status_callback)
               interactive.py ── guided menu flow → agent + approval

  OPTIONAL WEB:
    quarr/api/app.py (FastAPI) ──uses──> agent, persistence, reporter
      routes: /engagements  /state  /findings  /query  /report
      quarr/api/websocket.py ── WS_Channel (broadcast status_callback events)
    quarr/ui/  ── static dashboard consuming the API + WS
```

### CLI Rendering Flow

```
command "findings"
  └─> render.findings_table(state)      # rich Table, severity colors
command agent query
  └─> progress.spinner("Agent thinking")
        └─> agent.run(query, status_callback=progress.update)
  └─> render.result_panel(result)
```

`rich` availability is detected once; a `PlainRenderer` implements the same interface for fallback (Req 1.6, 8.3).

## Components and Interfaces

### `quarr/cli/render.py`

```python
class Renderer(Protocol):
    def findings_table(self, state) -> None: ...
    def state_panel(self, state) -> None: ...
    def scope_panel(self, engagement) -> None: ...
    def history_table(self, state) -> None: ...
    def result_panel(self, text: str) -> None: ...
    def sessions_table(self, sessions: list) -> None: ...

class RichRenderer(Renderer): ...     # uses rich.Console, Table, Panel
class PlainRenderer(Renderer): ...    # current print-based behavior

SEVERITY_STYLE = {"critical":"bold red","high":"red","medium":"yellow",
                  "low":"cyan","info":"dim"}

def get_renderer() -> Renderer:       # RichRenderer if rich importable else Plain
```

### `quarr/cli/progress.py`

```python
class ProgressReporter:
    def __init__(self, renderer): ...
    async def status(self, message: str) -> None:   # matches agent status_callback
    def spinner(self, label: str): ...               # context manager
    def plan_progress(self, total: int): ...         # step X/N
```

Uses `rich.progress`/`rich.status`. The agent's existing `status_callback` (async `print_status`) is replaced by `ProgressReporter.status`, so live updates render in place without corrupting logs (Req 2.4, 2.5). Log output is routed to stderr (Phase 1), progress to stdout, avoiding interleave.

### `quarr/cli/interactive.py`

```python
async def run_interactive(agent, renderer) -> None:
    # numbered menu: 1) define scope 2) run discovery 3) review findings
    #                4) generate report 5) back to command loop
    # each choice validated; dangerous actions pass through PolicyEngine
    #   (Phase 4 approval prompt) before execution
```

Reuses the agent and policy path; adds no new authorization logic (Req 3.4, 3.7).

### `main.py` (refactor)

```python
def parse_args() -> argparse.Namespace:
    # --interactive, --engagement, --scope (append), --backend, --report, --help

async def main():
    args = parse_args()
    renderer = get_renderer()
    ... existing backend detection + engagement setup (or load --engagement) ...
    if args.interactive: await run_interactive(agent, renderer)
    else: await command_loop(agent, renderer)   # existing commands, richer output
```

Command loop keeps every existing command and the auto-save behavior (Req 8.1, 8.2, 8.4).

### Optional: `quarr/api/app.py` (FastAPI)

```python
app = FastAPI(title="QUARR API")

@app.get("/engagements")            -> persistence.list_engagements()
@app.get("/engagements/{id}/state") -> load_state(id).model_dump() (redacted)
@app.get("/engagements/{id}/findings")
@app.post("/engagements/{id}/query")  # body: {query}; runs agent turn (auth gated)
@app.post("/engagements/{id}/report") # body: {type}; returns report
```

- Pydantic request/response models; input validation returns structured 4xx.
- Tool-executing endpoints run through `PolicyEngine.authorize` with the session role (Phase 4).
- Responses redacted via Secrets_Manager (Req 5.6). OpenAPI served automatically by FastAPI (Req 5.7).

### Optional: `quarr/api/websocket.py` (WS_Channel)

```python
class ConnectionManager:
    def __init__(self): self.active: list[WebSocket] = []
    async def connect(ws): ...
    async def broadcast(event: dict): ...    # redacted payloads
    def disconnect(ws): ...

# agent status_callback wired to manager.broadcast for live events
```

Handles multiple clients and clean disconnect (Req 7.4, 7.6); never sends secrets/raw evidence (Req 7.5).

### Optional: `quarr/ui/`

Lightweight static dashboard (plain HTML/JS or a small SPA) that calls the REST endpoints and subscribes to the WS channel. Severity colors match `SEVERITY_STYLE`; all API-derived content inserted via `textContent`/escaping to prevent XSS (Req 6.4, 6.5). Shows a clear error state when the API is unreachable (Req 6.6).

## Data Models

No changes to core models. New presentation-only structures live in `quarr/cli/`. API request/response Pydantic models live in `quarr/api/` and are derived from existing models (redacted). WS event payload: `{type, timestamp, data}` with redacted `data`.

## Error Handling

- Missing `rich` → `PlainRenderer` fallback; CLI still starts (Req 8.3).
- Invalid CLI args → `argparse` prints usage, exits non-zero (Req 4.4).
- API input validation → structured 4xx (FastAPI/Pydantic).
- WS client disconnect → connection removed, agent unaffected (Req 7.4).
- Progress indicators finalize cleanly on error (context managers) (Req 2.6).

## Testing Strategy

- **render**: `get_renderer` returns `PlainRenderer` when `rich` import is monkeypatched away; `RichRenderer.findings_table` produces output containing finding titles (capture rich Console with `record=True`); severity styling map complete.
- **progress**: `ProgressReporter.status` is awaitable and matches the agent callback signature; spinner context manager enters/exits without error; plan progress formats "X/N".
- **interactive**: menu input validation (invalid choice re-prompts via injected input fn); dangerous action triggers Phase 4 approval (injected `prompt_fn`); "back" returns to loop.
- **argparse**: flags parse; `--scope` repeatable; invalid arg exits non-zero; `--engagement` loads a saved session (mock persistence).
- **CLI migration**: all existing commands still handled; auto-save called after run and on quit (mock `save_state`).
- **API (optional)**: FastAPI `TestClient` — list engagements, get state (redacted, no secrets), findings; query endpoint gated by authorization (mock agent); report endpoint returns content; invalid input → 4xx; OpenAPI schema served at `/openapi.json`.
- **websocket (optional)**: `TestClient` websocket — connect, receive a broadcast event, disconnect cleanly; payload contains no secret patterns.

All tests run offline; the API uses `TestClient` (no live server). Web UI is verified by API contract tests plus a manual smoke.

## Dependencies Added

```
rich>=13.0.0
fastapi>=0.110.0      # optional (Web API)
uvicorn>=0.29.0       # optional (serve API)
```

`argparse` and `asyncio` are stdlib. `httpx` (present) backs FastAPI's `TestClient`. FastAPI/uvicorn are only required if the optional Web UI is built; the CLI needs only `rich` (with plain fallback).
