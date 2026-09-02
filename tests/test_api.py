"""Tests for the optional FastAPI web backend (Phase 6, Req 5)."""

import pytest
from fastapi.testclient import TestClient

from quarr.api import app as api_app
from quarr.api.app import app, set_agent_factory
from quarr.core import persistence


@pytest.fixture
def client(tmp_path, monkeypatch, populated_state):
    # Isolate engagements storage and seed one engagement.
    monkeypatch.setattr(persistence, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    # Seed a secret into a finding description to prove redaction.
    populated_state.findings[0].description = "leaked api_key=SUPERSECRETKEY123"
    persistence.save_state(populated_state)
    set_agent_factory(None)  # reset
    return TestClient(app), populated_state.engagement.id


@pytest.mark.integration
def test_list_engagements(client):
    c, eng_id = client
    resp = c.get("/engagements")
    assert resp.status_code == 200
    ids = [e["id"] for e in resp.json()["engagements"]]
    assert eng_id in ids


@pytest.mark.integration
def test_get_state_redacts_secrets(client):
    c, eng_id = client
    resp = c.get(f"/engagements/{eng_id}/state")
    assert resp.status_code == 200
    body = resp.text
    assert "SUPERSECRETKEY123" not in body
    assert "***REDACTED***" in body


@pytest.mark.integration
def test_get_findings(client):
    c, eng_id = client
    resp = c.get(f"/engagements/{eng_id}/findings")
    assert resp.status_code == 200
    assert len(resp.json()["findings"]) >= 1


@pytest.mark.integration
def test_get_state_404(client):
    c, _ = client
    assert c.get("/engagements/NOPE/state").status_code == 404


@pytest.mark.integration
def test_query_empty_is_422(client):
    c, eng_id = client
    assert c.post(f"/engagements/{eng_id}/query", json={"query": ""}).status_code == 422


@pytest.mark.integration
def test_query_without_agent_is_503(client):
    c, eng_id = client
    resp = c.post(f"/engagements/{eng_id}/query", json={"query": "scan"})
    assert resp.status_code == 503


@pytest.mark.integration
def test_query_with_agent_factory(client):
    c, eng_id = client

    class FakeAgent:
        def __init__(self, engagement):
            self.engagement = engagement

        async def run(self, query, status_callback=None):
            return "done: password: leaked123"

    set_agent_factory(lambda eng: FakeAgent(eng))
    try:
        resp = c.post(f"/engagements/{eng_id}/query", json={"query": "discover"})
        assert resp.status_code == 200
        # Result is redacted.
        assert "leaked123" not in resp.json()["result"]
    finally:
        set_agent_factory(None)


@pytest.mark.integration
def test_report_endpoint(client):
    c, eng_id = client
    resp = c.post(f"/engagements/{eng_id}/report", json={"type": "executive"})
    assert resp.status_code == 200
    assert "EXECUTIVE" in resp.json()["content"]


@pytest.mark.integration
def test_openapi_served(client):
    c, _ = client
    assert c.get("/openapi.json").status_code == 200


@pytest.mark.integration
def test_dashboard_root(client):
    c, _ = client
    resp = c.get("/")
    assert resp.status_code == 200
    assert "QUARR" in resp.text


@pytest.mark.integration
def test_dashboard_is_xss_safe():
    # The shipped dashboard must use textContent, never innerHTML, for
    # API-derived content.
    from pathlib import Path
    import quarr.api.app as app_mod

    ui = Path(app_mod.__file__).resolve().parent.parent / "ui" / "index.html"
    assert ui.exists()
    html = ui.read_text()
    assert "textContent" in html
    assert "innerHTML" not in html
