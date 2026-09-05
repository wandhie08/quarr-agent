"""Tests for the professional FastAPI backend (Phase 6): auth, RBAC, endpoints."""

import pytest
from fastapi.testclient import TestClient

from quarr.api import security as sec
from quarr.api.app import app, set_agent_factory
from quarr.core import persistence
from quarr.core.config import Settings


@pytest.fixture
def client(tmp_path, monkeypatch, populated_state):
    monkeypatch.setattr(persistence, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    # Deterministic users for tests.
    from quarr.api.auth import UserStore
    store = UserStore()
    store.add("admin", "adminpw", role="admin")
    store.add("op", "oppw", role="operator")
    store.add("viewer", "viewpw", role="viewer")
    s = Settings(_env_file=None, jwt_secret="x" * 40)
    sec.init_security(s, store)

    populated_state.findings[0].description = "leaked api_key=SUPERSECRETKEY123"
    persistence.save_state(populated_state)
    set_agent_factory(None)
    return TestClient(app), populated_state.engagement.id


def _login(c, username, password):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ---- auth ----

@pytest.mark.integration
def test_login_success(client):
    c, _ = client
    body = _login(c, "admin", "adminpw")
    assert body["role"] == "admin"
    assert body["access_token"] and body["refresh_token"]


@pytest.mark.integration
def test_login_invalid(client):
    c, _ = client
    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


@pytest.mark.integration
def test_protected_requires_token(client):
    c, _ = client
    assert c.get("/api/engagements").status_code == 401


@pytest.mark.integration
def test_refresh_flow(client):
    c, _ = client
    body = _login(c, "op", "oppw")
    r = c.post("/api/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert r.status_code == 200
    assert r.json()["access_token"]


@pytest.mark.integration
def test_me_endpoint(client):
    c, _ = client
    tok = _login(c, "viewer", "viewpw")["access_token"]
    r = c.get("/api/auth/me", headers=_auth(tok))
    assert r.json()["role"] == "viewer"


# ---- RBAC ----

@pytest.mark.integration
def test_viewer_cannot_create_engagement(client):
    c, _ = client
    tok = _login(c, "viewer", "viewpw")["access_token"]
    r = c.post("/api/engagements", json={"name": "X", "allowed_targets": ["10.0.0.1"]},
               headers=_auth(tok))
    assert r.status_code == 403


@pytest.mark.integration
def test_operator_can_create_engagement(client):
    c, _ = client
    tok = _login(c, "op", "oppw")["access_token"]
    r = c.post("/api/engagements", json={"name": "New Eng", "allowed_targets": ["10.0.0.5"]},
               headers=_auth(tok))
    assert r.status_code == 201
    assert r.json()["id"].startswith("ENG-")


@pytest.mark.integration
def test_only_admin_deletes(client):
    c, eng_id = client
    op_tok = _login(c, "op", "oppw")["access_token"]
    assert c.delete(f"/api/engagements/{eng_id}", headers=_auth(op_tok)).status_code == 403
    admin_tok = _login(c, "admin", "adminpw")["access_token"]
    assert c.delete(f"/api/engagements/{eng_id}", headers=_auth(admin_tok)).status_code == 200


# ---- data endpoints ----

@pytest.mark.integration
def test_list_and_get_engagement(client):
    c, eng_id = client
    tok = _login(c, "viewer", "viewpw")["access_token"]
    assert eng_id in [e["id"] for e in c.get("/api/engagements", headers=_auth(tok)).json()["engagements"]]
    r = c.get(f"/api/engagements/{eng_id}", headers=_auth(tok))
    assert r.status_code == 200
    assert "severity_counts" in r.json()


@pytest.mark.integration
def test_state_redacts_secrets(client):
    c, eng_id = client
    tok = _login(c, "viewer", "viewpw")["access_token"]
    body = c.get(f"/api/engagements/{eng_id}/state", headers=_auth(tok)).text
    assert "SUPERSECRETKEY123" not in body
    assert "***REDACTED***" in body


@pytest.mark.integration
def test_findings_and_update(client):
    c, eng_id = client
    tok = _login(c, "op", "oppw")["access_token"]
    findings = c.get(f"/api/engagements/{eng_id}/findings", headers=_auth(tok)).json()["findings"]
    assert findings
    fid = findings[0]["id"]
    r = c.patch(f"/api/engagements/{eng_id}/findings/{fid}",
                json={"status": "reported"}, headers=_auth(tok))
    assert r.status_code == 200


@pytest.mark.integration
def test_timeline_and_history_and_evidence(client):
    c, eng_id = client
    tok = _login(c, "viewer", "viewpw")["access_token"]
    assert c.get(f"/api/engagements/{eng_id}/timeline", headers=_auth(tok)).status_code == 200
    assert c.get(f"/api/engagements/{eng_id}/tool-history", headers=_auth(tok)).status_code == 200
    ev = c.get(f"/api/engagements/{eng_id}/evidence", headers=_auth(tok))
    assert ev.status_code == 200
    assert "chain_verified" in ev.json()


@pytest.mark.integration
def test_report_preview_and_download(client):
    c, eng_id = client
    tok = _login(c, "viewer", "viewpw")["access_token"]
    r = c.post(f"/api/engagements/{eng_id}/report", json={"type": "executive"},
               headers=_auth(tok))
    assert r.status_code == 200 and "EXECUTIVE" in r.json()["content"]
    dl = c.get(f"/api/engagements/{eng_id}/report/download?fmt=html&type=technical",
               headers=_auth(tok))
    assert dl.status_code == 200
    assert "attachment" in dl.headers.get("content-disposition", "")
    jdl = c.get(f"/api/engagements/{eng_id}/report/download?fmt=json",
                headers=_auth(tok))
    assert jdl.status_code == 200


@pytest.mark.integration
def test_dedup_endpoint(client):
    c, eng_id = client
    tok = _login(c, "op", "oppw")["access_token"]
    r = c.post(f"/api/engagements/{eng_id}/dedup?dry_run=true", headers=_auth(tok))
    assert r.status_code == 200
    assert "merged" in r.json()


@pytest.mark.integration
def test_query_gated_and_redacted(client):
    c, eng_id = client
    op_tok = _login(c, "op", "oppw")["access_token"]
    # No agent factory → 503.
    assert c.post(f"/api/engagements/{eng_id}/query", json={"query": "scan"},
                  headers=_auth(op_tok)).status_code == 503

    class FakeAgent:
        def __init__(self, eng): pass
        async def run(self, q, status_callback=None):
            return "done password: leaked123"

    set_agent_factory(lambda eng: FakeAgent(eng))
    try:
        r = c.post(f"/api/engagements/{eng_id}/query", json={"query": "scan"},
                   headers=_auth(op_tok))
        assert r.status_code == 200
        assert "leaked123" not in r.json()["result"]
    finally:
        set_agent_factory(None)


@pytest.mark.integration
def test_security_headers_present(client):
    c, _ = client
    r = c.get("/api/engagements",
              headers=_auth(_login(c, "viewer", "viewpw")["access_token"]))
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"


@pytest.mark.integration
def test_openapi_served(client):
    c, _ = client
    assert c.get("/openapi.json").status_code == 200
