"""Tests for the optional WebSocket channel (Phase 6, Req 7)."""

import pytest
from fastapi.testclient import TestClient

from quarr.api.app import app
from quarr.api.websocket import ConnectionManager


@pytest.mark.integration
def test_ws_connect_receive_broadcast():
    client = TestClient(app)
    with client.websocket_connect("/ws") as ws:
        # The endpoint sends an initial event on connect.
        msg = ws.receive_json()
        assert msg["type"] == "connected"
        assert msg["data"] == "ok"


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
