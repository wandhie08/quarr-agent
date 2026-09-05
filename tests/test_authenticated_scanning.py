"""Tests for authenticated scanning support + the http_request tool (bug-bounty).

- Auth passthrough: nuclei (vulnerability_scan) and gobuster (web_content_discovery)
  accept headers/cookie and inject them safely, rejecting shell metacharacters.
- http_request: general HTTP primitive for manual verification (method/URL
  validation, header parsing, secret redaction). httpx is mocked.
"""

import httpx
import pytest

from quarr.tools import api_security as api
from quarr.tools import registry as reg

# =========================================================================== #
# Auth passthrough on core web scanners
# =========================================================================== #

@pytest.mark.unit
class TestAuthPassthrough:
    def _capture(self, monkeypatch):
        cap = {}
        monkeypatch.setattr(reg, "_run_command", lambda cmd, timeout=180: cap.setdefault("cmd", cmd) or "OK")
        return cap

    def test_nuclei_adds_auth_header_and_cookie(self, monkeypatch):
        cap = self._capture(monkeypatch)
        reg.vulnerability_scan("http://t/", headers="Authorization: Bearer abc123", cookie="session=xyz")
        assert "-H 'Authorization: Bearer abc123'" in cap["cmd"]
        assert "-H 'Cookie: session=xyz'" in cap["cmd"]

    def test_nuclei_without_auth_unchanged(self, monkeypatch):
        cap = self._capture(monkeypatch)
        reg.vulnerability_scan("http://t/")
        assert "-H " not in cap["cmd"]

    def test_nuclei_rejects_header_injection(self):
        out = reg.vulnerability_scan("http://t/", headers="X: y; rm -rf /")
        assert "[ERROR]" in out and "metacharacter" in out

    def test_gobuster_adds_header_and_cookie(self, monkeypatch):
        cap = self._capture(monkeypatch)
        reg.web_content_discovery("http://t/", headers="Authorization: Bearer abc", cookie="sess=1")
        assert "-H 'Authorization: Bearer abc'" in cap["cmd"]
        assert "-c sess=1" in cap["cmd"]

    def test_gobuster_rejects_cookie_injection(self):
        out = reg.web_content_discovery("http://t/", cookie="a=b`whoami`")
        assert "[ERROR]" in out and "metacharacter" in out

    def test_header_validator_requires_colon(self):
        with pytest.raises(ValueError):
            reg._validate_header("no-colon-here")


# =========================================================================== #
# http_request tool
# =========================================================================== #

def _resp(status=200, text="ok", headers=None):
    req = httpx.Request("GET", "http://x")
    return httpx.Response(status, text=text, headers=headers or {}, request=req)


@pytest.mark.unit
class TestHttpRequest:
    def test_rejects_bad_method(self):
        assert "[ERROR]" in api.http_request("EVIL", "http://x")

    def test_rejects_bad_url(self):
        assert "[ERROR]" in api.http_request("GET", "not a url")

    def test_get_returns_status_and_headers(self, monkeypatch):
        monkeypatch.setattr(httpx, "request",
                            lambda *a, **k: _resp(200, "hello", {"content-type": "text/html"}))
        out = api.http_request("GET", "http://site/page")
        assert "Status: 200" in out
        assert "content-type: text/html" in out
        assert "hello" in out

    def test_parses_headers_and_cookie(self, monkeypatch):
        seen = {}

        def fake_request(method, url, headers=None, content=None, timeout=20.0, follow_redirects=False):
            seen.update(headers or {})
            seen["_method"] = method
            return _resp(200, "ok")

        monkeypatch.setattr(httpx, "request", fake_request)
        api.http_request("POST", "http://site/api",
                         headers="Authorization: Bearer T;;X-Api: 9", cookie="session=abc", body='{"x":1}')
        assert seen["_method"] == "POST"
        assert seen.get("Authorization") == "Bearer T"
        assert seen.get("X-Api") == "9"
        assert seen.get("Cookie") == "session=abc"

    def test_body_is_sent(self, monkeypatch):
        captured = {}

        def fake_request(method, url, headers=None, content=None, timeout=20.0, follow_redirects=False):
            captured["content"] = content
            return _resp(200, "ok")

        monkeypatch.setattr(httpx, "request", fake_request)
        api.http_request("PUT", "http://site/x", body='{"password":"p"}')
        assert captured["content"] == b'{"password":"p"}'

    def test_response_body_secrets_redacted(self, monkeypatch):
        monkeypatch.setattr(httpx, "request",
                            lambda *a, **k: _resp(200, 'token: ghp_' + 'A' * 30))
        out = api.http_request("GET", "http://site/")
        assert "ghp_" + "A" * 30 not in out
        assert "REDACTED" in out

    def test_network_error_handled(self, monkeypatch):
        def boom(*a, **k):
            raise httpx.ConnectError("refused")
        monkeypatch.setattr(httpx, "request", boom)
        out = api.http_request("GET", "http://site/")
        assert "[ERROR]" in out and "failed" in out.lower()

    def test_registered_in_registry(self):
        assert "http_request" in reg.TOOL_REGISTRY
