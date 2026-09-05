"""Tests for the Live Console WebSocket (Phase 6 professional)."""

import pytest
from fastapi.testclient import TestClient

from quarr.api import security as sec
from quarr.api.app import app
from quarr.api.auth import UserStore
from quarr.api.live import set_live_agent_factory
from quarr.core import persistence
from quarr.core.config import Settings
from quarr.core.models import RiskLevel


@pytest.fixture
def client(tmp_path, monkeypatch, populated_state):
    monkeypatch.setattr(persistence, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
    store = UserStore()
    store.add("admin", "adminpw", role="admin")
    store.add("op", "oppw", role="operator")
    store.add("viewer", "viewpw", role="viewer")
    sec.init_security(Settings(_env_file=None, jwt_secret="x" * 40), store)
    persistence.save_state(populated_state)
    set_live_agent_factory(None)
    return TestClient(app), populated_state.engagement.id


def _token(c, u, p):
    return c.post("/api/auth/login", json={"username": u, "password": p}).json()["access_token"]


@pytest.mark.integration
def test_live_requires_auth(client):
    c, eng_id = client
    with c.websocket_connect(f"/ws/live?engagement={eng_id}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "unauthorized" in msg["data"]


@pytest.mark.integration
def test_live_viewer_forbidden(client):
    c, eng_id = client
    tok = _token(c, "viewer", "viewpw")
    with c.websocket_connect(f"/ws/live?token={tok}&engagement={eng_id}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
        assert "forbidden" in msg["data"]


@pytest.mark.integration
def test_live_engagement_not_found(client):
    c, _ = client
    tok = _token(c, "op", "oppw")
    with c.websocket_connect(f"/ws/live?token={tok}&engagement=NOPE") as ws:
        assert ws.receive_json()["type"] == "error"


@pytest.mark.integration
def test_live_run_streams_status_and_result(client):
    c, eng_id = client
    tok = _token(c, "op", "oppw")

    class FakeAgent:
        def __init__(self, engagement, approval):
            self.engagement = engagement
            self.approval = approval
            from quarr.core.models import PentestState
            self.state = PentestState()
            self.state.engagement = engagement

        async def run(self, query, status_callback=None):
            if status_callback:
                await status_callback("Agent thinking...")
            return "Assessment complete."

    set_live_agent_factory(lambda eng, approval: FakeAgent(eng, approval))
    try:
        with c.websocket_connect(f"/ws/live?token={tok}&engagement={eng_id}") as ws:
            assert ws.receive_json()["type"] == "connected"
            ws.send_json({"type": "run", "query": "scan"})
            status = ws.receive_json()
            assert status["type"] == "status"
            result = ws.receive_json()
            assert result["type"] == "result"
            assert "complete" in result["data"].lower()
    finally:
        set_live_agent_factory(None)


@pytest.mark.integration
def test_live_approval_flow_denied(client):
    c, eng_id = client
    tok = _token(c, "op", "oppw")

    class DangerAgent:
        def __init__(self, engagement, approval):
            self.engagement = engagement
            self.approval = approval
            from quarr.core.models import PentestState
            self.state = PentestState()
            self.state.engagement = engagement

        async def run(self, query, status_callback=None):
            # Ask for approval on a CRITICAL tool; denial raises.
            from quarr.core.exceptions import PolicyViolationError
            try:
                await self.approval.gate_async("hashcat", "10.10.10.20", RiskLevel.CRITICAL)
            except PolicyViolationError:
                return "denied by operator"
            return "ran dangerous tool"

    set_live_agent_factory(lambda eng, approval: DangerAgent(eng, approval))
    try:
        with c.websocket_connect(f"/ws/live?token={tok}&engagement={eng_id}") as ws:
            assert ws.receive_json()["type"] == "connected"
            ws.send_json({"type": "run", "query": "crack hashes"})
            req = ws.receive_json()
            assert req["type"] == "approval_request"
            assert req["tool"] == "hashcat"
            ws.send_json({"type": "approval_response", "approved": False})
            result = ws.receive_json()
            assert result["type"] == "result"
            assert "denied" in result["data"].lower()
    finally:
        set_live_agent_factory(None)


@pytest.mark.integration
def test_live_approval_flow_approved(client):
    c, eng_id = client
    tok = _token(c, "admin", "adminpw")

    class DangerAgent:
        def __init__(self, engagement, approval):
            self.engagement = engagement
            self.approval = approval
            from quarr.core.models import PentestState
            self.state = PentestState()
            self.state.engagement = engagement

        async def run(self, query, status_callback=None):
            await self.approval.gate_async("hydra", "10.10.10.20", RiskLevel.HIGH)
            return "tool executed"

    set_live_agent_factory(lambda eng, approval: DangerAgent(eng, approval))
    try:
        with c.websocket_connect(f"/ws/live?token={tok}&engagement={eng_id}") as ws:
            assert ws.receive_json()["type"] == "connected"
            ws.send_json({"type": "run", "query": "brute force"})
            req = ws.receive_json()
            assert req["type"] == "approval_request"
            ws.send_json({"type": "approval_response", "approved": True})
            result = ws.receive_json()
            assert result["type"] == "result"
            assert "executed" in result["data"].lower()
    finally:
        set_live_agent_factory(None)
