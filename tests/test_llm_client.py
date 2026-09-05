"""Unit tests for LLM client error mapping and retry (Phase 1, Req 2 & 10)."""

import httpx
import pytest

from quarr.core.exceptions import (
    LLMConnectionError,
    LLMRateLimitError,
    LLMResponseError,
    LLMTimeoutError,
)
from quarr.core.llm_client import OpenAIClient, _do_request, build_retry


def _install_post(monkeypatch, *, status=200, json_body=None, exc=None, resp_headers=None):
    async def _post(self, url, json=None, headers=None):  # noqa: A002
        if exc is not None:
            raise exc
        req = httpx.Request("POST", url)
        return httpx.Response(status, json=json_body or {},
                              headers=resp_headers, request=req)
    monkeypatch.setattr(httpx.AsyncClient, "post", _post)


@pytest.mark.unit
async def test_connect_error_maps(monkeypatch):
    _install_post(monkeypatch, exc=httpx.ConnectError("refused"))
    with pytest.raises(LLMConnectionError):
        await _do_request("http://x", {"messages": []}, 5.0, backend="ollama")


@pytest.mark.unit
async def test_timeout_maps(monkeypatch):
    _install_post(monkeypatch, exc=httpx.ReadTimeout("slow"))
    with pytest.raises(LLMTimeoutError) as ei:
        await _do_request("http://x", {"messages": []}, 5.0, backend="ollama")
    assert "timeout" in ei.value.context


@pytest.mark.unit
async def test_429_maps_to_rate_limit(monkeypatch):
    _install_post(monkeypatch, status=429, resp_headers={"retry-after": "7"})
    with pytest.raises(LLMRateLimitError) as ei:
        await _do_request("http://x", {"messages": []}, 5.0, backend="openai")
    assert ei.value.context["retry_after"] == "7"


@pytest.mark.unit
async def test_500_maps_to_response_error(monkeypatch):
    _install_post(monkeypatch, status=500, json_body={"error": "boom"})
    with pytest.raises(LLMResponseError) as ei:
        await _do_request("http://x", {"messages": []}, 5.0, backend="openai")
    assert ei.value.context["status_code"] == 500


@pytest.mark.unit
async def test_openai_chat_success_parses_tool_calls(monkeypatch):
    body = {
        "choices": [{
            "message": {
                "content": "",
                "tool_calls": [{
                    "function": {"name": "network_discovery",
                                 "arguments": '{"target": "10.0.0.1"}'}
                }],
            }
        }]
    }
    _install_post(monkeypatch, status=200, json_body=body)
    client = OpenAIClient(model="gpt-4o-mini", api_key="sk-test")
    result = await client.chat([{"role": "user", "content": "scan"}], tools=[{}])
    assert result["tool_calls"][0]["function"]["name"] == "network_discovery"
    assert result["tool_calls"][0]["function"]["arguments"] == {"target": "10.0.0.1"}


@pytest.mark.unit
async def test_openai_401_not_retried(monkeypatch):
    calls = {"n": 0}

    async def _post(self, url, json=None, headers=None):  # noqa: A002
        calls["n"] += 1
        req = httpx.Request("POST", url)
        return httpx.Response(401, json={"error": "unauthorized"}, request=req)
    monkeypatch.setattr(httpx.AsyncClient, "post", _post)

    client = OpenAIClient(model="gpt-4o-mini", api_key="sk-test")
    with pytest.raises(LLMResponseError):
        await client.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 1  # no retry on 401


@pytest.mark.unit
async def test_build_retry_retries_connection_error(monkeypatch):
    calls = {"n": 0}

    @build_retry(max_attempts=3, initial=0.0, maximum=0.0, multiplier=1.0)
    async def _flaky():
        calls["n"] += 1
        raise LLMConnectionError("down")

    with pytest.raises(LLMConnectionError):
        await _flaky()
    assert calls["n"] == 3  # retried up to max attempts


@pytest.mark.unit
async def test_build_retry_does_not_retry_response_error(monkeypatch):
    calls = {"n": 0}

    @build_retry(max_attempts=3, initial=0.0, maximum=0.0, multiplier=1.0)
    async def _bad():
        calls["n"] += 1
        raise LLMResponseError("400", context={"status_code": 400})

    with pytest.raises(LLMResponseError):
        await _bad()
    assert calls["n"] == 1  # not retried


@pytest.mark.unit
async def test_resilient_client_opens_breaker_on_repeated_failures(monkeypatch):
    from quarr.core.circuit_breaker import CircuitState
    from quarr.core.config import Settings
    from quarr.core.llm_client import OllamaClient, ResilientLLMClient

    # Fast retries, low breaker threshold for the test.
    settings = Settings(
        _env_file=None,
        llm_max_retries=1,
        backoff_initial=0.0,
        backoff_max=0.0,
        backoff_multiplier=1.0,
        circuit_breaker_threshold=2,
        rate_limit_tpm=6000,
        rate_limit_burst=100,
    )
    _install_post(monkeypatch, exc=httpx.ConnectError("refused"))
    client = ResilientLLMClient(OllamaClient(model="m"), settings=settings)

    for _ in range(2):
        with pytest.raises(LLMConnectionError):
            await client.chat([{"role": "user", "content": "hi"}])
    assert client._breaker.state == CircuitState.OPEN

    # Now the breaker rejects fast without hitting the network.
    calls = {"n": 0}

    async def _post_spy(self, url, json=None, headers=None):  # noqa: A002
        calls["n"] += 1
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx.AsyncClient, "post", _post_spy)

    with pytest.raises(LLMConnectionError):
        await client.chat([{"role": "user", "content": "hi"}])
    assert calls["n"] == 0  # rejected by open breaker, no network call
