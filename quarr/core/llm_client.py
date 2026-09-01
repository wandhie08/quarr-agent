"""
llm_client.py - Multi-Backend LLM Client

Mendukung:
1. Ollama (local) — WhiteRabbitNeo, Qwen, Llama, dll
2. OpenAI API — GPT-4o, GPT-4o-mini, dll

Auto-detect backend dari environment variables:
- OPENAI_API_KEY set → gunakan OpenAI
- Tidak ada → gunakan Ollama (default)

Kedua backend mengembalikan format response yang sama.
"""

import json
import os
import re
import httpx
import logging
from typing import Optional, Dict, Any, List


logger = logging.getLogger("quarr.llm")

# === Defaults ===
OLLAMA_API = "http://localhost:11434/api/chat"
OLLAMA_DEFAULT_MODEL = "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest"

OPENAI_API = "https://api.openai.com/v1/chat/completions"
OPENAI_DEFAULT_MODEL = "gpt-4o-mini"


# ============================================================
# Base class
# ============================================================

class BaseLLMClient:
    """Base class — semua client harus return format yang sama."""

    def __init__(self, model: str, temperature: float = 0.2, timeout: float = 360.0):
        self.model = model
        self.temperature = temperature
        self.timeout = timeout

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        max_tokens: int = 1024,
    ) -> Dict[str, Any]:
        """
        Returns:
        {
            "content": str,
            "tool_calls": [{"function": {"name": str, "arguments": dict}}],
            "raw": dict
        }
        """
        raise NotImplementedError

    @staticmethod
    def parse_tool_call_from_text(text: str) -> Optional[Dict]:
        """Parse tool call dari text response (fallback)."""
        text = text.strip()

        # Direct JSON
        if text.startswith("{") and text.endswith("}"):
            try:
                data = json.loads(text)
                return BaseLLMClient._normalize_tool_call(data)
            except json.JSONDecodeError:
                pass

        # Code fences
        code_blocks = re.findall(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
        for block in code_blocks:
            try:
                data = json.loads(block.strip())
                result = BaseLLMClient._normalize_tool_call(data)
                if result:
                    return result
            except json.JSONDecodeError:
                continue

        # Brute force JSON extraction
        brace_depth = 0
        start = -1
        for i, ch in enumerate(text):
            if ch == '{':
                if brace_depth == 0:
                    start = i
                brace_depth += 1
            elif ch == '}':
                brace_depth -= 1
                if brace_depth == 0 and start >= 0:
                    candidate = text[start:i + 1]
                    try:
                        data = json.loads(candidate)
                        result = BaseLLMClient._normalize_tool_call(data)
                        if result:
                            return result
                    except json.JSONDecodeError:
                        pass
                    start = -1
        return None

    @staticmethod
    def _normalize_tool_call(data: dict) -> Optional[Dict]:
        if not isinstance(data, dict):
            return None
        if "tool" in data:
            return {"function": {"name": data["tool"], "arguments": data.get("args", data.get("arguments", {}))}}
        if "name" in data and "arguments" in data:
            return {"function": {"name": data["name"], "arguments": data["arguments"]}}
        if "function" in data and isinstance(data.get("function"), dict) and "name" in data["function"]:
            return data
        return None

    @staticmethod
    def build_tool_prompt(tools: List[Dict]) -> str:
        """Build tool description untuk prompt-based fallback."""
        lines = [
            "AVAILABLE TOOLS:",
            "When you need to use a tool, respond with ONLY a JSON object:",
            '{"tool": "<tool_name>", "args": {<arguments>}}',
            "",
            "Do NOT include any text before or after the JSON when calling a tool.",
            "Only call ONE tool at a time.",
            "",
            "Tools:",
        ]
        for tool in tools:
            func = tool.get("function", tool)
            name = func.get("name", "unknown")
            desc = func.get("description", "")
            params = func.get("parameters", {})
            props = params.get("properties", {})
            required = params.get("required", [])

            param_strs = []
            for pname, pinfo in props.items():
                req = " (required)" if pname in required else " (optional)"
                pdesc = pinfo.get("description", "")
                enum = pinfo.get("enum")
                enum_str = f", options: {enum}" if enum else ""
                param_strs.append(f"    - {pname}{req}: {pdesc}{enum_str}")

            lines.append(f"\n  {name}: {desc}")
            lines.append("  Parameters:")
            lines.extend(param_strs)

        lines.append("")
        lines.append("If you have enough information to answer without a tool, respond with plain text (no JSON).")
        return "\n".join(lines)

    @staticmethod
    def inject_tool_prompt(messages: List[Dict], tool_prompt: str) -> List[Dict]:
        result = []
        injected = False
        for msg in messages:
            if msg["role"] == "system" and not injected:
                result.append({"role": "system", "content": msg["content"] + "\n\n" + tool_prompt})
                injected = True
            else:
                result.append(msg)
        if not injected:
            result.insert(0, {"role": "system", "content": tool_prompt})
        return result


# ============================================================
# OpenAI Client
# ============================================================

class OpenAIClient(BaseLLMClient):
    """Client untuk OpenAI API (GPT-4o, GPT-4o-mini, dll)."""

    def __init__(
        self,
        model: str = OPENAI_DEFAULT_MODEL,
        api_key: str = None,
        temperature: float = 0.2,
        timeout: float = 120.0,
    ):
        super().__init__(model, temperature, timeout)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY not set")
        self.base_url = OPENAI_API

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        max_tokens: int = 1024,
    ) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
        }

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=30.0)
        ) as client:
            response = await client.post(self.base_url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()

        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content", "") or ""
        content = content.strip()

        # Parse tool calls
        raw_tool_calls = message.get("tool_calls", [])
        tool_calls = []
        for tc in raw_tool_calls:
            func = tc.get("function", {})
            args = func.get("arguments", "{}")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append({
                "function": {
                    "name": func.get("name", ""),
                    "arguments": args,
                }
            })

        return {
            "content": content,
            "tool_calls": tool_calls,
            "raw": data,
        }


# ============================================================
# Ollama Client
# ============================================================

class OllamaClient(BaseLLMClient):
    """Client untuk Ollama API (local LLM)."""

    def __init__(
        self,
        model: str = OLLAMA_DEFAULT_MODEL,
        base_url: str = OLLAMA_API,
        temperature: float = 0.2,
        timeout: float = 360.0,
    ):
        super().__init__(model, temperature, timeout)
        self.base_url = base_url
        self._native_tools_supported: Optional[bool] = None

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: Optional[List[Dict]] = None,
        max_tokens: int = 1024,
    ) -> Dict[str, Any]:

        if tools and self._native_tools_supported is None:
            result = await self._try_native_tools(messages, tools, max_tokens)
            if result is not None:
                self._native_tools_supported = True
                logger.info(f"Model {self.model} supports native tool calling")
                return result
            else:
                self._native_tools_supported = False
                logger.info(f"Model {self.model}: using prompt-based fallback")

        if tools and self._native_tools_supported:
            return await self._chat_native(messages, tools, max_tokens)
        elif tools:
            return await self._chat_prompt_based(messages, tools, max_tokens)
        else:
            return await self._chat_plain(messages, max_tokens)

    async def _try_native_tools(self, messages, tools, max_tokens) -> Optional[Dict]:
        payload = self._build_payload(messages, max_tokens, tools=tools)
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=30.0)) as client:
            response = await client.post(self.base_url, json=payload)
            if response.status_code == 400 and "does not support tools" in response.text:
                return None
            response.raise_for_status()
            return self._parse_ollama_response(response.json())

    async def _chat_native(self, messages, tools, max_tokens) -> Dict:
        payload = self._build_payload(messages, max_tokens, tools=tools)
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=30.0)) as client:
            response = await client.post(self.base_url, json=payload)
            response.raise_for_status()
            return self._parse_ollama_response(response.json())

    async def _chat_prompt_based(self, messages, tools, max_tokens) -> Dict:
        tool_prompt = self.build_tool_prompt(tools)
        augmented = self.inject_tool_prompt(messages, tool_prompt)
        payload = self._build_payload(augmented, max_tokens)
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=30.0)) as client:
            response = await client.post(self.base_url, json=payload)
            response.raise_for_status()
            data = response.json()
        content = data.get("message", {}).get("content", "").strip()
        tool_calls = []
        parsed = self.parse_tool_call_from_text(content)
        if parsed:
            tool_calls = [parsed]
        return {"content": content, "tool_calls": tool_calls, "raw": data}

    async def _chat_plain(self, messages, max_tokens) -> Dict:
        payload = self._build_payload(messages, max_tokens)
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=30.0)) as client:
            response = await client.post(self.base_url, json=payload)
            response.raise_for_status()
            data = response.json()
        content = data.get("message", {}).get("content", "").strip()
        return {"content": content, "tool_calls": [], "raw": data}

    def _build_payload(self, messages, max_tokens, tools=None):
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = tools
        return payload

    def _parse_ollama_response(self, data: dict) -> Dict:
        message = data.get("message", {})
        content = message.get("content", "").strip()
        tool_calls = message.get("tool_calls", [])

        normalized = []
        for tc in tool_calls:
            if "function" in tc:
                normalized.append(tc)
            elif "name" in tc:
                normalized.append({"function": {"name": tc["name"], "arguments": tc.get("arguments", {})}})

        if not normalized and content:
            parsed = self.parse_tool_call_from_text(content)
            if parsed:
                normalized = [parsed]

        return {"content": content, "tool_calls": normalized, "raw": data}


# ============================================================
# Factory
# ============================================================

def create_llm_client(
    model: str = None,
    api_key: str = None,
    backend: str = None,
) -> BaseLLMClient:
    """
    Buat LLM client berdasarkan konfigurasi.

    Auto-detect:
    - OPENAI_API_KEY ada → OpenAI
    - Tidak ada → Ollama

    Override dengan parameter backend="openai" atau backend="ollama".
    """
    openai_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    # Auto-detect
    if backend is None:
        if openai_key:
            backend = "openai"
        else:
            backend = "ollama"

    if backend == "openai":
        model = model or os.environ.get("OPENAI_MODEL", OPENAI_DEFAULT_MODEL)
        logger.info(f"Using OpenAI backend: {model}")
        return OpenAIClient(model=model, api_key=openai_key)

    else:
        model = model or os.environ.get("OLLAMA_MODEL", OLLAMA_DEFAULT_MODEL)
        logger.info(f"Using Ollama backend: {model}")
        return OllamaClient(model=model)
