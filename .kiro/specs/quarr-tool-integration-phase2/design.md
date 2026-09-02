# Design Document

## Overview

Phase 2 introduces a structured tool-integration layer under `quarr/tools/integrations/` and `quarr/tools/parsers/`, plus a hardened executor (`quarr/tools/executor.py`) and availability checker (`quarr/tools/checker.py`). The existing `quarr/tools/registry.py` — which today builds command strings inline and calls `_run_command` — is refactored so its handlers delegate to the new integration classes while keeping identical tool names and callable signatures.

### Goals

- Eliminate string-built commands in favor of argument-vector execution (`shell=False`).
- Make tool output structured and testable via pure parser functions and fixtures.
- Detect missing tools gracefully instead of surfacing raw subprocess errors.
- Preserve full backward compatibility with `agent.py` dispatch and the 90+ registered tool names.

### Non-Goals

- Advanced target/path validation beyond current regex is deferred to Phase 4; Phase 2 uses the existing `_validate_target`/`_validate_url` helpers plus a minimal path allowlist for credential tools.
- Test coverage tooling and CI belong to Phase 3.

## Architecture

```
                        ┌─────────────────────────┐
                        │      registry.py         │
                        │  handler(target,...) ──┐ │  (unchanged signatures)
                        └────────────────────────┼─┘
                                                 │ delegates to
                                                 ▼
                        ┌─────────────────────────────────────┐
                        │   integrations/base.py               │
                        │   ToolIntegration (ABC)              │
                        │     build_command() ─┐               │
                        │     parse_output()   │  run():        │
                        │     binary_name      │   check →      │
                        │                      │   execute →    │
                        │                      │   parse        │
                        └───────────┬──────────┴──────┬─────────┘
                                    │                 │
                     ┌──────────────▼───┐     ┌───────▼────────────┐
                     │ checker.py       │     │ executor.py        │
                     │ ToolChecker      │     │ SecureExecutor     │
                     │  which+cache     │     │  argv, shell=False │
                     └──────────────────┘     │  timeout, capture  │
                                              └───────┬────────────┘
                                                      │ raw output
                                                      ▼
                     ┌────────────────────────────────────────────┐
                     │ parsers/  (pure functions)                  │
                     │  nmap_xml → [Host,Service]                  │
                     │  nikto → [Finding]                          │
                     │  nuclei_jsonl → [Finding]                   │
                     └────────────────────────────────────────────┘

Concrete integrations (each subclass ToolIntegration):
  nmap.py  nikto.py  masscan.py  nuclei.py
  sqlmap.py  dirsearch.py  whatweb.py  sslscan.py
  hydra.py  hashcat.py  john.py
```

### Execution Flow

```
registry handler(target=...)
  └─> NmapIntegration().run(target=..., ports=...)
        ├─ ToolChecker.is_available("nmap")  → else ToolNotFoundError
        ├─ build_command(**kw) → ["nmap","-sV","-oX","-", target]
        ├─ SecureExecutor.run(argv, timeout) → (stdout, stderr, code, ms)
        ├─ parse_output(stdout) → {"hosts":[...], "services":[...]}
        └─ return ToolResult(success, raw_output, parsed, duration_ms)
```

## Components and Interfaces

### 1. `quarr/tools/executor.py` — SecureExecutor

```python
@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int

class SecureExecutor:
    ARG_ALLOWLIST = re.compile(r"^[A-Za-z0-9._:/@=,\-\+]+$")  # values must match

    def run(self, argv: list[str], timeout: int,
            cwd: str | None = None, env: dict | None = None) -> ExecResult:
        # 1. validate argv non-empty; each arg matches ARG_ALLOWLIST
        #    (flags like -sV and values like 10.0.0.1 pass; ';', '|', '$(' fail)
        # 2. resolve binary via shutil.which; missing → ToolNotFoundError
        # 3. subprocess.run(argv, shell=False, capture_output=True,
        #                    text=True, timeout=timeout, cwd=cwd, env=env)
        # 4. TimeoutExpired → ToolTimeoutError; return ExecResult otherwise
```

Design points (Req 2):
- `shell=False` always; argv only. No `_run_command_shell`-style path for integrations.
- Each argument is validated against `ARG_ALLOWLIST`; arguments failing validation raise `ArgumentValidationError`. This blocks `;`, `|`, `&`, `$()`, backticks, spaces-in-single-arg injection.
- `env` defaults to a minimal copy (PATH only) unless explicit overrides provided, so secrets in the parent env are not inherited by tools (Req 2.8).
- Non-zero exit is not automatically fatal (many scanners exit non-zero on "findings"); integrations decide via `parse_output`. `ToolExecutionError` is raised only when the integration marks the code as failure.

### 2. `quarr/tools/checker.py` — ToolChecker

```python
class ToolChecker:
    _cache: dict[str, bool] = {}
    _versions: dict[str, str] = {}

    @classmethod
    def is_available(cls, binary: str) -> bool: ...        # shutil.which + cache
    @classmethod
    def version(cls, binary: str) -> str | None: ...        # best-effort `--version`
    @classmethod
    def check_all(cls, binaries: list[str]) -> dict[str,bool]: ...
    @classmethod
    def report(cls) -> str: ...                              # startup capability summary
```

### 3. `quarr/tools/integrations/base.py` — ToolIntegration

```python
@dataclass
class ToolResult:
    tool_name: str
    success: bool
    raw_output: str
    parsed: dict
    duration_ms: int
    error: str | None = None

class ToolIntegration(ABC):
    binary_name: str
    name: str
    category: str
    risk_level: RiskLevel
    default_timeout: int = 180
    requires_scope: bool = True

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]: ...
    @abstractmethod
    def parse_output(self, raw: str) -> dict: ...

    def run(self, **kwargs) -> ToolResult:
        if not ToolChecker.is_available(self.binary_name):
            raise ToolNotFoundError(self.binary_name,
                context={"tool": self.name})
        argv = self.build_command(**kwargs)
        try:
            res = SecureExecutor().run(argv, self.default_timeout)
        except QuarrError:
            raise
        parsed = self.parse_output(res.stdout)
        return ToolResult(self.name, True, res.stdout, parsed, res.duration_ms)
```

### 4. `quarr/tools/parsers/` — Pure Parsers

- `nmap.py`: `parse_nmap_xml(xml: str) -> dict{hosts, services}` using `xml.etree.ElementTree`. Reuses existing `quarr/parsers/network.py` domain shapes where possible.
- `nikto.py`: `parse_nikto(raw: str) -> dict{findings}` (JSON if `-Format json`, else line regex).
- `nuclei.py`: `parse_nuclei_jsonl(raw: str) -> dict{findings}` — one JSON object per line with `template-id`, `info.severity`, `matched-at`.
- Each raises `ToolOutputParseError` on malformed/empty input and is side-effect free (Req 4.5, 4.6).

### 5. Concrete Integrations

Each integration file defines `build_command` and `parse_output`. Representative command vectors:

| Tool | binary | build_command (argv) | parser |
|---|---|---|---|
| Nmap | `nmap` | `["nmap","-sV","-oX","-", target]` (+ `-p ports`) | `parse_nmap_xml` |
| Nikto | `nikto` | `["nikto","-host",url,"-Format","json","-output","-"]` | `parse_nikto` |
| Masscan | `masscan` | `["masscan",target,"-p",ports,"-oJ","-"]` | json ports |
| Nuclei | `nuclei` | `["nuclei","-u",url,"-jsonl","-silent"]` | `parse_nuclei_jsonl` |
| SQLMap | `sqlmap` | `["sqlmap","-u",url,"--batch","--level","1","--risk","1"]` | text summary |
| Dirsearch | `dirsearch` | `["dirsearch","-u",url,"-q","--format=plain"]` | path list |
| WhatWeb | `whatweb` | `["whatweb","--log-json=-", url]` | json fingerprint |
| SSLScan | `sslscan` | `["sslscan","--no-colour", host]` | tls summary |
| Hydra | `hydra` | `["hydra","-L",userlist,"-P",passlist, target, service]` | success lines (redacted) |
| Hashcat | `hashcat` | `["hashcat","-m",mode,hashfile,wordlist,"--quiet"]` | cracked count (redacted) |
| John | `john` | `["john","--wordlist="+wordlist, hashfile]` | cracked count (redacted) |

Risk classification (Req 7.4): Hydra/Hashcat/John = HIGH/CRITICAL. SQLMap = HIGH. Nmap/WhatWeb/SSLScan = LOW/MEDIUM.

Credential tools validate wordlist/hashfile paths against an allowlist of directories (`/usr/share/wordlists`, engagement dir) before execution (Req 7.7), and redact any cracked secret in output summaries (Req 7.6).

### 6. Registry Refactor — `quarr/tools/registry.py`

Existing handlers keep their signatures. Bodies delegate:

```python
def network_discovery(target: str) -> str:
    integ = NmapIntegration(mode="discovery")
    try:
        result = integ.run(target=target)
    except ToolNotFoundError:
        return "[TOOL NOT INSTALLED] nmap is not available on this host."
    return _summarize(result)   # human string; parsed attached for agent merge
```

- A thin `_summarize(ToolResult) -> str` keeps the existing "return a string" contract for `agent.py` (Req 8.2, 8.6).
- To also give the agent structured data, handlers may set a module-level/last-result hook or return a richer object the agent already knows how to read via the parser path in `agent.py`. The safe minimal approach: return the summary string (unchanged contract) and let the agent's existing `parse_tool_output` continue to work; structured `parsed` is additionally exposed through `ToolResult` for future use.
- All 90+ tool names remain; only handler internals change (Req 8.5).

## Data Models

Reuses existing `quarr/core/models.py`: `Host`, `Service`, `Finding`, `Observation`, `RiskLevel`. New dataclasses `ExecResult` and `ToolResult` are internal to the tools package. No breaking schema changes.

## Error Handling

- Missing binary → `ToolNotFoundError` at `run()`; registry handler converts to a friendly string (Req 8.3).
- Timeout → `ToolTimeoutError` from executor; recorded as failed `ToolExecution` by the Phase 1 agent hardening.
- Bad args / injection attempt → `ArgumentValidationError` from executor before any process spawns.
- Malformed output → `ToolOutputParseError` from parser; integration returns `ToolResult(success=False, error=...)` rather than crashing the loop.
- All errors carry `context` and integrate with Phase 1 structured logging and audit.

## Testing Strategy

All parsers and integrations are unit-tested with recorded fixtures under `tests/fixtures/` (Phase 3 expands this).

- **executor**: argv with metacharacters → `ArgumentValidationError`; missing binary → `ToolNotFoundError`; timeout via a `sleep` argv → `ToolTimeoutError`; happy path with `echo`.
- **checker**: `is_available` true/false via monkeypatched `shutil.which`; caching verified.
- **parsers**: feed recorded Nmap XML, Nuclei JSONL, Nikto JSON fixtures → assert extracted hosts/services/findings; malformed input → `ToolOutputParseError`.
- **integrations**: mock `SecureExecutor.run` to return fixture output; assert `build_command` argv shape and `parse_output` result; assert credential tools redact secrets and validate paths.
- **registry**: assert migrated names still resolve; unavailable tool returns friendly string (monkeypatch checker); `len(TOOL_REGISTRY) >= 90` still holds (existing smoke test must stay green).

Fixtures avoid requiring the real binaries so tests run in CI without Kali tools installed.

## Dependencies Added

No new runtime dependencies are strictly required (stdlib `subprocess`, `shutil`, `xml.etree`, `json`, `re`). Optional: none. Test fixtures are plain text/JSON files.
