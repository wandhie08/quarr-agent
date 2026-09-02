# Requirements Document

## Introduction

This document specifies the requirements for **Phase 6: UI & UX** of the QUARR Agent. The current interface (`main.py`) uses plain `print`/`input` with a command loop (state, findings, scope, history, report, executive, technical, export, save, load, sessions, plan, retest). Phase 6 improves the CLI experience with the `rich` library (styled output, tables, progress bars) and a guided interactive mode, and optionally adds a FastAPI web backend with a lightweight dashboard and WebSocket real-time updates.

The CLI improvements are the primary, required deliverable. The Web UI is optional (marked 🟢 in TASKS.md) and can be skipped for MVP; its requirements are included so the spec is complete if the team chooses to build it.

## Glossary

- **CLI_Renderer**: The presentation layer using `rich` for styled terminal output
- **Progress_Reporter**: Component showing scan/tool progress via progress bars/spinners
- **Interactive_Mode**: A guided, menu-driven flow for step-by-step assessment
- **Command_Loop**: The existing REPL in `main.py` handling built-in commands and agent queries
- **Web_API**: The optional FastAPI backend exposing engagement/agent operations over REST
- **Dashboard**: The optional web frontend displaying state, findings, and reports
- **WS_Channel**: The optional WebSocket channel pushing real-time agent updates

## Requirements

### Requirement 1: Rich CLI Output

**User Story:** As an operator, I want styled, readable terminal output, so that findings, state, and history are easy to scan visually.

#### Acceptance Criteria

1. THE CLI_Renderer SHALL use the `rich` library for terminal rendering in `main.py`
2. THE CLI_Renderer SHALL display findings in a table with columns: severity (color-coded), title, asset, status, confidence
3. THE CLI_Renderer SHALL display engagement scope and state summaries using styled panels
4. THE CLI_Renderer SHALL display tool execution history as a table with status icons and timestamps
5. THE CLI_Renderer SHALL color-code severities consistently (critical/high/medium/low/info)
6. WHEN the terminal does not support color, THE CLI_Renderer SHALL degrade gracefully to plain text
7. THE existing command set (state, findings, scope, history, report, executive, technical, export, save, load, sessions, plan, retest, help, quit) SHALL be preserved with improved rendering

### Requirement 2: Progress Indicators

**User Story:** As an operator, I want progress bars and spinners, so that I know the agent is working and how long operations take.

#### Acceptance Criteria

1. THE Progress_Reporter SHALL display a spinner or progress indicator while the agent is thinking or a tool is running
2. THE Progress_Reporter SHALL show tool name and elapsed time during long-running tool executions
3. WHEN a multi-step plan executes, THE Progress_Reporter SHALL show step progress (e.g., "Step 2/5")
4. THE Progress_Reporter SHALL integrate with the agent status callback so live status updates render in place
5. THE Progress_Reporter SHALL not corrupt terminal output when interleaved with log messages
6. THE Progress_Reporter SHALL clear or finalize indicators cleanly on completion or error

### Requirement 3: Interactive Mode

**User Story:** As a new user, I want a guided interactive mode, so that I can perform an assessment step by step without memorizing commands.

#### Acceptance Criteria

1. THE Interactive_Mode SHALL provide a guided menu for common workflows: define scope, run discovery, review findings, generate report
2. THE Interactive_Mode SHALL be launchable via a CLI flag (e.g., `--interactive`) or a command in the loop
3. THE Interactive_Mode SHALL prompt with numbered choices and validate input
4. WHEN a dangerous action is selected, THE Interactive_Mode SHALL integrate with the Phase 4 approval workflow before executing
5. THE Interactive_Mode SHALL allow returning to the main command loop at any point
6. THE Interactive_Mode SHALL display contextual help for each step
7. THE Interactive_Mode SHALL preserve all safety checks (policy, scope, approval) present in the standard loop

### Requirement 4: CLI Argument Parsing

**User Story:** As a power user, I want command-line flags, so that I can configure runs without interactive prompts.

#### Acceptance Criteria

1. THE CLI SHALL parse arguments using `argparse`
2. THE CLI SHALL support flags for: `--interactive`, `--engagement <id>` (load existing), `--scope <target>` (repeatable), `--backend <openai|ollama>`, `--report <type>`
3. WHEN `--engagement` is provided, THE CLI SHALL load that saved session at startup
4. WHEN invalid arguments are provided, THE CLI SHALL print usage and exit with a non-zero status
5. THE CLI SHALL retain the current interactive setup flow when no arguments are provided
6. THE CLI SHALL provide `--help` documenting all flags

### Requirement 5: Web API Backend (Optional)

**User Story:** As a team, I want an optional REST API, so that the agent can be driven from a web dashboard.

#### Acceptance Criteria

1. THE Web_API SHALL be implemented with FastAPI under `quarr/api/`
2. THE Web_API SHALL expose endpoints to: list engagements, get engagement state, get findings, start an agent query, and generate a report
3. THE Web_API SHALL reuse the existing core modules (agent, persistence, reporter) without duplicating logic
4. THE Web_API SHALL apply the Phase 4 authorization (permissions, scope, approval) on operations that execute tools
5. THE Web_API SHALL validate all request inputs and return structured error responses
6. THE Web_API SHALL never expose secrets in responses (redacted via Phase 4 Secrets_Manager)
7. THE Web_API SHALL include an OpenAPI schema served by FastAPI

### Requirement 6: Web Dashboard (Optional)

**User Story:** As an operator, I want a web dashboard, so that I can view state, findings, and reports in a browser.

#### Acceptance Criteria

1. THE Dashboard SHALL be served under `quarr/ui/` (static assets or a lightweight SPA)
2. THE Dashboard SHALL display engagement list, current state, findings table, and report preview
3. THE Dashboard SHALL consume the Web_API endpoints
4. THE Dashboard SHALL color-code severities consistently with the CLI
5. THE Dashboard SHALL escape/render tool-derived content safely to prevent XSS
6. THE Dashboard SHALL degrade gracefully when the API is unavailable, showing a clear error state

### Requirement 7: Real-Time Updates (Optional)

**User Story:** As an operator, I want real-time updates, so that I can watch the agent's progress live in the dashboard.

#### Acceptance Criteria

1. THE WS_Channel SHALL be implemented in `quarr/api/websocket.py`
2. THE WS_Channel SHALL push agent status updates, new findings, and tool execution events to connected clients
3. THE WS_Channel SHALL reuse the agent status callback mechanism to source events
4. WHEN a client disconnects, THE WS_Channel SHALL clean up the connection without affecting the agent
5. THE WS_Channel SHALL not transmit secrets or raw sensitive evidence over the socket
6. THE WS_Channel SHALL handle multiple concurrent clients

### Requirement 8: Non-Breaking CLI Migration

**User Story:** As an existing user, I want the improved CLI to keep working exactly as before for current commands, so that muscle memory and scripts are not broken.

#### Acceptance Criteria

1. THE improved CLI SHALL preserve all existing command names and their behavior
2. THE improved CLI SHALL preserve the auto-save on quit and after each run behavior
3. WHEN `rich` is not installed, THE CLI SHALL fall back to plain output rather than failing to start
4. THE CLI SHALL keep the existing engagement setup and backend auto-detection behavior
5. THE improved rendering SHALL not change the semantics of agent execution or state
