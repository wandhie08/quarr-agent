"""Unit tests for LLM client parsing, Ollama fallback, and factory.

test_llm_client.py already covers HTTP error mapping, retry, and the circuit
breaker. This suite targets the previously-uncovered logic that makes the agent
work with LOCAL models lacking native tool-calling:

  - BaseLLMClient.parse_tool_call_from_text: direct JSON, code-fence, and
    brute-force-embedded JSON extraction, plus the no-tool case.
  - _normalize_tool_call: the {tool/args}, {name/arguments}, and {function}
    shapes, and rejection of junk.
  - build_tool_prompt / inject_tool_prompt: prompt-based fallback scaffolding.
  - OllamaClient: native-tools probe -> 400 -> prompt-based fallback chain,
    the native success path, plain (no-tools) chat, and response normalization.
  - create_llm_client: backend auto-detect, explicit override, and the
    resilient wrapper.

All HTTP is mocked; no real Ollama/OpenAI/network is touched.
"""

import httpx
import pytest

from quarr.core.llm_client import (
    BaseLLMClient,
    OllamaClient,
    ResilientLLMClient,
    create_llm_client,
)

TOOLS = [{
    "function": {
        "name": "network_discovery",
        "description": "Discover live hosts",
        "parameters": {
            "properties": {"target": {"description": "IP/CIDR", "enum": ["a", "b"]}},
            "required": ["target"],
        },
    }
}]


def _install_post(monkeypatch, responder):
    """responder(call_index, url, json, headers) -> httpx.Response."""
    state = {"n": 0}

    async def _post(self, url, json=None, headers=None):  # noqa: A002
        state["n"] += 1
        return responder(state["n"], url, json, headers)

    monkeypatch.setattr(httpx.AsyncClient, "post", _post)
    return state


def _resp(status, *, json_body=None, text=None):
    req = httpx.Request("POST", "http://x")
    if text is not None:
        return httpx.Response(status, text=text, request=req)
    return httpx.Response(status, json=json_body or {}, request=req)


# =========================================================================== #
# parse_tool_call_from_text
# =========================================================================== #

@pytest.mark.unit
class TestParseToolCallFromText:
    def test_direct_json_tool_args(self):
        out = BaseLLMClient.parse_tool_call_from_text('{"tool": "nmap", "args": {"target": "x"}}')
        assert out == {"function": {"name": "nmap", "arguments": {"target": "x"}}}

    def test_code_fence_json(self):
        text = 'Sure:\n```json\n{"tool": "sqli_scan", "args": {"t": 1}}\n```'
        out = BaseLLMClient.parse_tool_call_from_text(text)
        assert out["function"]["name"] == "sqli_scan"

    def test_embedded_json_brute_force(self):
        text = 'I will run {"name": "xss_scan", "arguments": {"u": "a"}} to verify.'
        out = BaseLLMClient.parse_tool_call_from_text(text)
        assert out["function"]["name"] == "xss_scan"
        assert out["function"]["arguments"] == {"u": "a"}

    def test_plain_text_returns_none(self):
        assert BaseLLMClient.parse_tool_call_from_text("just my analysis, no tool") is None

    def test_malformed_json_returns_none(self):
        assert BaseLLMClient.parse_tool_call_from_text("{not: valid json,,,}") is None


@pytest.mark.unit
class TestNormalizeToolCall:
    def test_tool_args_shape(self):
        assert BaseLLMClient._normalize_tool_call({"tool": "a", "args": {"x": 1}}) == \
            {"function": {"name": "a", "arguments": {"x": 1}}}

    def test_name_arguments_shape(self):
        assert BaseLLMClient._normalize_tool_call({"name": "a", "arguments": {}}) == \
            {"function": {"name": "a", "arguments": {}}}

    def test_function_shape_passthrough(self):
        data = {"function": {"name": "a", "arguments": {"k": "v"}}}
        assert BaseLLMClient._normalize_tool_call(data) == data

    def test_junk_returns_none(self):
        assert BaseLLMClient._normalize_tool_call({"foo": "bar"}) is None
        assert BaseLLMClient._normalize_tool_call("not a dict") is None


# =========================================================================== #
# build_tool_prompt / inject_tool_prompt
# =========================================================================== #

@pytest.mark.unit
class TestToolPrompt:
    def test_build_tool_prompt_includes_tool_and_params(self):
        prompt = BaseLLMClient.build_tool_prompt(TOOLS)
        assert "network_discovery" in prompt
        assert "target" in prompt and "(required)" in prompt
        assert "options: ['a', 'b']" in prompt
        assert '{"tool": "<tool_name>", "args": {<arguments>}}' in prompt

    def test_inject_into_existing_system_message(self):
        msgs = [{"role": "system", "content": "SYS"}, {"role": "user", "content": "hi"}]
        out = BaseLLMClient.inject_tool_prompt(msgs, "TOOLPROMPT")
        assert out[0]["role"] == "system"
        assert "SYS" in out[0]["content"] and "TOOLPROMPT" in out[0]["content"]
        assert out[1] == {"role": "user", "content": "hi"}

    def test_inject_prepends_when_no_system_message(self):
        msgs = [{"role": "user", "content": "hi"}]
        out = BaseLLMClient.inject_tool_prompt(msgs, "TOOLPROMPT")
        assert out[0] == {"role": "system", "content": "TOOLPROMPT"}
        assert out[1]["role"] == "user"


# =========================================================================== #
# OllamaClient backend paths
# =========================================================================== #

@pytest.mark.unit
class TestOllamaClient:
    async def test_native_tools_unsupported_falls_back_to_prompt(self, monkeypatch):
        def responder(n, url, json, headers):
            if n == 1:  # native probe → 400 "does not support tools"
                return _resp(400, text="this model does not support tools")
            # prompt-based fallback → JSON tool call in content
            return _resp(200, json_body={"message": {
                "content": '{"tool": "network_discovery", "args": {"target": "10.0.0.5"}}'}})

        _install_post(monkeypatch, responder)
        c = OllamaClient(model="m")
        r = await c.chat([{"role": "user", "content": "scan"}], tools=TOOLS)

        assert c._native_tools_supported is False
        assert r["tool_calls"][0]["function"]["name"] == "network_discovery"
        assert r["tool_calls"][0]["function"]["arguments"] == {"target": "10.0.0.5"}

    async def test_native_tools_supported_path(self, monkeypatch):
        def responder(n, url, json, headers):
            # Probe succeeds with a native tool_calls array.
            return _resp(200, json_body={"message": {
                "content": "",
                "tool_calls": [{"function": {"name": "service_enumeration",
                                             "arguments": {"target": "10.0.0.5"}}}],
            }})

        _install_post(monkeypatch, responder)
        c = OllamaClient(model="m")
        r = await c.chat([{"role": "user", "content": "enum"}], tools=TOOLS)

        assert c._native_tools_supported is True
        assert r["tool_calls"][0]["function"]["name"] == "service_enumeration"

    async def test_plain_chat_no_tools(self, monkeypatch):
        _install_post(monkeypatch, lambda n, u, j, h: _resp(
            200, json_body={"message": {"content": "  final analysis  "}}))
        c = OllamaClient(model="m")
        r = await c.chat([{"role": "user", "content": "summarize"}])
        assert r["content"] == "final analysis"
        assert r["tool_calls"] == []

    async def test_parse_normalizes_name_only_tool_call(self, monkeypatch):
        # Ollama sometimes returns {name, arguments} instead of {function:{...}}.
        _install_post(monkeypatch, lambda n, u, j, h: _resp(200, json_body={"message": {
            "content": "",
            "tool_calls": [{"name": "sqli_scan", "arguments": {"target": "u"}}],
        }}))
        c = OllamaClient(model="m")
        c._native_tools_supported = True  # skip probe
        r = await c.chat([{"role": "user", "content": "test"}], tools=TOOLS)
        assert r["tool_calls"][0]["function"]["name"] == "sqli_scan"

    async def test_native_tool_calls_fallback_to_text_parse(self, monkeypatch):
        # No structured tool_calls, but content carries an embedded JSON call.
        _install_post(monkeypatch, lambda n, u, j, h: _resp(200, json_body={"message": {
            "content": '{"tool": "xss_scan", "args": {"u": "http://a"}}',
        }}))
        c = OllamaClient(model="m")
        c._native_tools_supported = True
        r = await c.chat([{"role": "user", "content": "test"}], tools=TOOLS)
        assert r["tool_calls"][0]["function"]["name"] == "xss_scan"


# =========================================================================== #
# create_llm_client factory
# =========================================================================== #

@pytest.mark.unit
class TestFactory:
    def test_autodetect_ollama_without_key(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        c = create_llm_client(backend=None, model="m")
        assert type(c).__name__ == "OllamaClient"

    def test_autodetect_openai_with_key(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        c = create_llm_client(backend=None)
        assert type(c).__name__ == "OpenAIClient"

    def test_explicit_backend_override(self, monkeypatch):
        # Even with a key present, explicit ollama wins.
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        c = create_llm_client(backend="ollama", model="m")
        assert type(c).__name__ == "OllamaClient"

    def test_resilient_wrapper_when_requested(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        c = create_llm_client(backend="ollama", model="m", resilient=True)
        assert isinstance(c, ResilientLLMClient)
        # The wrapper preserves the inner model for interface compatibility.
        assert c.model == "m"
