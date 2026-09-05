"""Unit tests for API security tools (quarr/tools/api_security.py).

Covers OpenAPI discovery, Excessive Data Exposure (API3), BOLA (API1), and JWT
analysis. httpx is mocked so no network is required.
"""

import base64
import hashlib
import hmac
import json

import httpx
import pytest

from quarr.tools import api_security as api


def _resp(status=200, json_body=None, text=None):
    req = httpx.Request("GET", "http://x")
    if text is not None:
        return httpx.Response(status, text=text, request=req)
    return httpx.Response(status, json=json_body or {}, request=req)


# =========================================================================== #
# URL validation
# =========================================================================== #

@pytest.mark.unit
class TestUrlValidation:
    def test_rejects_shell_metachars(self):
        with pytest.raises(ValueError):
            api._validate_url("http://x.com/;rm -rf /")

    def test_rejects_non_http(self):
        with pytest.raises(ValueError):
            api._validate_url("ftp://x.com")

    def test_accepts_parameterized_url(self):
        assert api._validate_url("http://h:5001/users/v1/{id}") == "http://h:5001/users/v1/{id}"


# =========================================================================== #
# api_endpoint_discovery
# =========================================================================== #

@pytest.mark.unit
class TestEndpointDiscovery:
    def test_parses_openapi_spec(self, monkeypatch):
        spec = {"info": {"title": "VAmPI"}, "paths": {
            "/users/v1/login": {"post": {}},
            "/users/v1/{username}": {"get": {}, "delete": {}},
        }}
        monkeypatch.setattr(api, "_get",
                            lambda url, headers=None, timeout=15.0:
                            _resp(200, spec) if url.endswith("/openapi.json") else _resp(404))
        out = api.api_endpoint_discovery("http://h:5001")
        assert "API SPEC FOUND" in out
        assert "VAmPI" in out
        assert "POST   /users/v1/login" in out
        assert "DELETE /users/v1/{username}" in out

    def test_no_spec_found(self, monkeypatch):
        monkeypatch.setattr(api, "_get", lambda url, headers=None, timeout=15.0: _resp(404))
        assert "No OpenAPI" in api.api_endpoint_discovery("http://h:5001")


# =========================================================================== #
# api_data_exposure_check (API3)
# =========================================================================== #

@pytest.mark.unit
class TestDataExposure:
    def test_flags_password_field(self, monkeypatch):
        body = {"users": [{"username": "a", "password": "p1"}]}
        monkeypatch.setattr(api, "_get", lambda url, headers=None, timeout=15.0: _resp(200, body))
        out = api.api_data_exposure_check("http://h/users/v1/_debug")
        assert "🚨 API3" in out and "password" in out

    def test_clean_response(self, monkeypatch):
        body = {"users": [{"username": "a", "email": "a@x.com"}]}
        monkeypatch.setattr(api, "_get", lambda url, headers=None, timeout=15.0: _resp(200, body))
        out = api.api_data_exposure_check("http://h/users/v1")
        assert "✅" in out and "🚨" not in out

    def test_non_json_response(self, monkeypatch):
        monkeypatch.setattr(api, "_get", lambda url, headers=None, timeout=15.0: _resp(200, text="<html>"))
        assert "not JSON" in api.api_data_exposure_check("http://h/")

    def test_parses_custom_headers(self, monkeypatch):
        seen = {}

        def fake_get(url, headers=None, timeout=15.0):
            seen.update(headers or {})
            return _resp(200, {"ok": 1})

        monkeypatch.setattr(api, "_get", fake_get)
        api.api_data_exposure_check("http://h/x", headers="Authorization: Bearer T;;X-Api: 9")
        assert seen.get("Authorization") == "Bearer T"
        assert seen.get("X-Api") == "9"


# =========================================================================== #
# api_bola_check (API1)
# =========================================================================== #

@pytest.mark.unit
class TestBOLA:
    def test_requires_id_placeholder(self):
        out = api.api_bola_check("http://h", "/users/v1/no-placeholder", "a", "b")
        assert "[ERROR]" in out and "{id}" in out

    def test_bola_confirmed(self, monkeypatch):
        def fake_get(url, headers=None, timeout=15.0):
            if url.endswith("/alice"):
                return _resp(200, {"user": "alice"})
            return _resp(200, {"user": "admin", "secret": "x"})  # other object accessible + differs
        monkeypatch.setattr(api, "_get", fake_get)
        out = api.api_bola_check("http://h", "/users/v1/{id}", "alice", "admin", token_a="tok")
        assert "BOLA CONFIRMED" in out

    def test_bola_denied(self, monkeypatch):
        def fake_get(url, headers=None, timeout=15.0):
            if url.endswith("/alice"):
                return _resp(200, {"user": "alice"})
            return _resp(403, text="forbidden")
        monkeypatch.setattr(api, "_get", fake_get)
        out = api.api_bola_check("http://h", "/users/v1/{id}", "alice", "admin", token_a="tok")
        assert "correctly denied" in out


# =========================================================================== #
# jwt_analyze
# =========================================================================== #

def _make_jwt(secret: str, alg="HS256", payload=None):
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    header = b64({"alg": alg, "typ": "JWT"})
    body = b64(payload or {"sub": "alice"})
    signing = f"{header}.{body}".encode()
    sig = hmac.new(secret.encode(), signing, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header}.{body}.{sig_b64}"


@pytest.mark.unit
class TestJWTAnalyze:
    def test_malformed_token(self):
        assert "[ERROR]" in api.jwt_analyze("not-a-jwt")

    def test_decodes_claims(self):
        tok = _make_jwt("supersecretnotcommon", payload={"sub": "bob", "role": "admin"})
        out = api.jwt_analyze(tok)
        assert "HS256" in out and '"sub": "bob"' in out

    def test_detects_weak_secret(self):
        tok = _make_jwt("secret")  # in the common-weak list
        out = api.jwt_analyze(tok)
        assert "🚨 HIGH" in out and "secret" in out

    def test_alg_none_flagged(self):
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        body = base64.urlsafe_b64encode(json.dumps({"sub": "x"}).encode()).decode().rstrip("=")
        out = api.jwt_analyze(f"{header}.{body}.")
        assert "alg=none" in out and "CRITICAL" in out


# =========================================================================== #
# registry wiring
# =========================================================================== #

@pytest.mark.unit
def test_api_tools_registered():
    from quarr.tools.registry import TOOL_REGISTRY
    for name in ("api_endpoint_discovery", "api_data_exposure_check",
                 "api_bola_check", "jwt_analyze"):
        assert name in TOOL_REGISTRY
