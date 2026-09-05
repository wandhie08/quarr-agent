"""
websocket.py - Real-time WebSocket channel (Phase 6, optional).

Broadcasts agent status/finding/tool events to connected clients. Payloads are
redacted via the Phase 4 secrets manager. Never transmits raw secrets/evidence.
"""

import json
from typing import Any

from fastapi import WebSocket

from quarr.core.logging import get_logger
from quarr.core.secrets import redact

logger = get_logger("quarr.api.ws")


class ConnectionManager:
    def __init__(self):
        self.active: list[Any] = []

    async def connect(self, websocket) -> None:
        await websocket.accept()
        self.active.append(websocket)
        logger.info("ws_connected", clients=len(self.active))

    def disconnect(self, websocket) -> None:
        if websocket in self.active:
            self.active.remove(websocket)
        logger.info("ws_disconnected", clients=len(self.active))

    @staticmethod
    def _redact_payload(event: dict[str, Any]) -> dict[str, Any]:
        safe = json.loads(json.dumps(event, default=str))

        def _scrub(value):
            if isinstance(value, str):
                return redact(value)
            if isinstance(value, dict):
                return {k: _scrub(v) for k, v in value.items()}
            if isinstance(value, list):
                return [_scrub(v) for v in value]
            return value

        # Recursively redact all string values (nested dicts/lists included).
        return _scrub(safe)

    async def broadcast(self, event: dict[str, Any]) -> None:
        payload = self._redact_payload(event)
        dead = []
        for ws in list(self.active):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def make_status_callback(self):
        """Return an async callback matching the agent status_callback signature."""

        async def _cb(message: str) -> None:
            await self.broadcast({"type": "status", "data": message})

        return _cb


# Shared manager instance used by the API app.
manager = ConnectionManager()


async def websocket_endpoint(websocket: WebSocket) -> None:
    """Authenticated WS endpoint: send a 'connected' event then keep the channel
    open. Requires a valid access token (?token=...) — the broadcast stream can
    carry agent status/finding events and must not be exposed anonymously."""
    from starlette.websockets import WebSocketDisconnect

    from quarr.api.live import _authenticate

    token = websocket.query_params.get("token")
    if _authenticate(token) is None:
        # Reject before accept() so anonymous clients cannot hold a connection.
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    await websocket.send_json({"type": "connected", "data": "ok"})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
