"""Tests for the optional WebSocket channel (Phase 6, Req 7)."""

import pytest
from fastapi.testclient import TestClient

from quarr.api.app import app
from quarr.api.websocket import ConnectionManager


@pytest.mark.integration
def test_ws_requires_auth_and_connects_with_token():
    from quarr.api import security as sec
    from quarr.api.auth import UserStore
    from quarr.core.config import Settings

    store = UserStore()
    store.add("op", "oppw", role="operator")
    sec.init_security(Settings(_env_file=None, jwt_secret="x" * 40), store)
    token = sec.token_service().access_token("op", "operator")

    client = TestClient(app)
    with client.websocket_connect(f"/ws?token={token}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "connected"
        assert msg["data"] == "ok"


@pytest.mark.integration
def test_ws_rejects_unauthenticated():
    from starlette.websockets import WebSocketDisconnect

    from quarr.api import security as sec
    from quarr.api.auth import UserStore
    from quarr.core.config import Settings

    sec.init_security(Settings(_env_file=None, jwt_secret="x" * 40), UserStore())
    client = TestClient(app)
    # No token → the endpoint closes before sending 'connected'.
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_json()


@pytest.mark.unit
async def test_broadcast_redacts_secrets():
    cm = ConnectionManager()
    sent = []

    class FakeWS:
        async def send_json(self, payload):
            sent.append(payload)

    cm.active.append(FakeWS())
    await cm.broadcast({"type": "finding", "data": "password: hunter2"})
    assert "hunter2" not in str(sent)
    assert "***REDACTED***" in str(sent)


@pytest.mark.unit
async def test_disconnect_removes_client():
    cm = ConnectionManager()

    class FakeWS:
        async def send_json(self, payload):
            raise RuntimeError("client gone")

    ws = FakeWS()
    cm.active.append(ws)
    # A failed send should prune the dead client.
    await cm.broadcast({"type": "status", "data": "x"})
    assert ws not in cm.active


@pytest.mark.unit
async def test_status_callback_broadcasts():
    cm = ConnectionManager()
    sent = []

    class FakeWS:
        async def send_json(self, payload):
            sent.append(payload)

    cm.active.append(FakeWS())
    cb = cm.make_status_callback()
    await cb("tool running")
    assert sent and sent[0]["type"] == "status"
