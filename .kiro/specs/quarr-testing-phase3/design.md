# Design Document

## Overview

Phase 3 turns the single ad-hoc smoke script into a structured pytest suite with fixtures, mocks, coverage, linting, and CI. It does not change production code except where a testability seam is required (e.g., allowing dependency injection of the LLM client or executor, most of which Phase 1/2 already provide).

### Directory Layout

```
tests/
├── conftest.py                 # shared fixtures
├── test_quarr.py               # existing smoke (kept/migrated)
├── test_llm_client.py          # unit
├── test_agent.py               # unit
├── test_tools.py               # unit
├── test_parsers.py             # unit
├── test_knowledge.py           # unit
├── fixtures/
│   ├── nmap.xml
│   ├── nuclei.jsonl
│   ├── nikto.json
│   └── hydra_output.txt
└── integration/
    ├── __init__.py
    ├── test_tool_chain.py
    ├── test_agent_flow.py
    └── test_reporter.py
```

## Architecture

### Configuration in `pyproject.toml`

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "unit: fast isolated unit tests",
    "integration: multi-component tests",
]
addopts = "-ra"

[tool.coverage.run]
source = ["quarr"]
omit = ["*/__pycache__/*", "*/venv/*", "tests/*"]

[tool.coverage.report]
show_missing = true
fail_under = 60

[tool.ruff]
target-version = "py313"
line-length = 100
exclude = ["venv", "__pycache__"]

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP"]

[tool.black]
line-length = 100
target-version = ["py313"]
```

`asyncio_mode = "auto"` lets `async def test_*` run without per-test decorators (Req 1.2).

### Mock LLM Design

The `QuarrAgent` accepts a constructed client (`create_llm_client`) internally. For tests, the Mock_LLM replaces `agent.client` after construction, or a fixture patches `create_llm_client`.

```python
class MockLLM:
    """Scripted async LLM client matching BaseLLMClient.chat() contract."""
    def __init__(self, script: list[dict]):
        # each item: {"content": str, "tool_calls": [...]}
        self._script = list(script)
    async def chat(self, messages, tools=None, max_tokens=1024) -> dict:
        if self._script:
            return self._script.pop(0)
        return {"content": "done", "tool_calls": [], "raw": {}}
```

A helper builds tool-call responses:

```python
def tool_call(name, **args):
    return {"content": "", "tool_calls": [
        {"function": {"name": name, "arguments": args}}], "raw": {}}
```

### HTTP Mocking for `llm_client`

`llm_client.py` uses `httpx.AsyncClient`. Tests monkeypatch the request via a transport stub or patch `httpx.AsyncClient.post` to return crafted responses (200 with tool_calls, 429, 500, connect error). This validates the Phase 1 error mapping without network.

```python
@pytest.fixture
def fake_post(monkeypatch):
    def _install(status=200, json_body=None, exc=None):
        async def _post(self, url, **kw):
            if exc: raise exc
            return httpx.Response(status, json=json_body or {}, request=...)
        monkeypatch.setattr(httpx.AsyncClient, "post", _post)
    return _install
```

### Subprocess Mocking for tools

Phase 2's `SecureExecutor.run` is the single seam. Tests monkeypatch it to return an `ExecResult` built from a fixture file, so integrations and the registry are tested without real binaries.

```python
@pytest.fixture
def mock_executor(monkeypatch):
    def _install(stdout, exit_code=0):
        def _run(self, argv, timeout, cwd=None, env=None):
            return ExecResult(stdout=stdout, stderr="", exit_code=exit_code, duration_ms=1)
        monkeypatch.setattr(SecureExecutor, "run", _run)
    return _install
```

## Components and Interfaces

### `tests/conftest.py` fixtures (Req 2)

- `sample_engagement` → `Engagement(name=..., allowed_targets=["10.10.10.0/24"])`
- `populated_state` → `PentestState` with a host, service, observation, and finding
- `tmp_engagements_dir` → monkeypatches `persistence.ENGAGEMENTS_DIR` to `tmp_path`
- `tmp_audit_path` → temporary audit-log path for Phase 1 `AuditLogger`
- `mock_llm` → `MockLLM` factory
- `fake_post` → httpx patcher
- `mock_executor` → executor patcher
- `load_fixture` → reads `tests/fixtures/<name>` and returns text

### Unit test coverage map (Req 3)

| File | Under test | Key cases |
|---|---|---|
| test_llm_client.py | `llm_client.py` | success+tool_calls parse; 429→`LLMRateLimitError`; 500→`LLMResponseError`; connect err→`LLMConnectionError` retried; 401 not retried |
| test_agent.py | `agent.py` | tool call updates state; tool exception caught, loop continues; policy violation fed back; 3 consecutive errors terminate |
| test_tools.py | integrations/registry | one tool per category via `mock_executor`; unavailable tool friendly string |
| test_parsers.py | parsers | fixture parse counts; malformed → `ToolOutputParseError` |
| test_knowledge.py | knowledge/base.py | `retrieve_knowledge`, `get_cwe_for_finding` (CWE-89 for SQLi), `get_cvss_range` |

### Integration tests (Req 4)

- `test_tool_chain.py`: `NmapIntegration().run(target=...)` with `mock_executor` feeding `nmap.xml` → assert parsed hosts/services.
- `test_agent_flow.py`: build `QuarrAgent`, set `agent.client = MockLLM([tool_call("network_discovery", target="10.10.10.20"), {"content":"Summary", "tool_calls":[]}])`, patch executor, run one turn → assert `state.tool_history` grew and hosts/observations updated.
- `test_reporter.py`: from `populated_state`, call `generate_executive_summary`, `generate_technical_report`, `export_json` → assert markers ("EXECUTIVE"/"TECHNICAL") and valid JSON.

### CI Pipeline `.github/workflows/test.yml` (Req 6)

```yaml
name: tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.13", cache: "pip" }
      - run: pip install -r requirements.txt
      - run: ruff check quarr/
      - run: black --check quarr/
      - run: pytest tests/ --cov=quarr --cov-report=term-missing --cov-report=html
      - uses: actions/upload-artifact@v4
        with: { name: coverage-html, path: htmlcov/ }
```

`fail_under = 60` in coverage config makes the pytest step fail if coverage drops (Req 5.6, 6.5).

## Data Models

No production data-model changes. Test-only helpers (`MockLLM`, fixture loaders) live in `tests/`.

## Error Handling

Tests assert on Phase 1 custom exceptions (type + `context` keys). Malformed-input tests assert `ToolOutputParseError`. No new error handling in production code is introduced by this phase.

## Testing Strategy

This phase *is* the testing strategy. Self-verification:
- `pytest tests/ -v` runs fully offline (all HTTP/subprocess/file effects mocked or in `tmp_path`).
- `pytest -m unit` and `pytest -m integration` select subsets.
- `pytest --cov=quarr --cov-report=term-missing` reports coverage; CI enforces `fail_under`.
- `ruff check quarr/` and `black --check quarr/` verify style.

Dependencies (`pytest`, `pytest-asyncio`, `pytest-cov`) are added in Phase 1/here; `ruff` and `black` are added to `requirements.txt` (or a dev-requirements section) in task 1.

## Dependencies Added

```
pytest-cov>=4.0.0
ruff>=0.4.0
black>=24.0.0
```

(`pytest`, `pytest-asyncio` already added in Phase 1.)
