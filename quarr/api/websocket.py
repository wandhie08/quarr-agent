"""
websocket.py - Real-time WebSocket channel (Phase 6, optional).

Broadcasts agent status/finding/tool events to connected clients. Payloads are
redacted via the Phase 4 secrets manager. Never transmits raw secrets/evidence.
"""

import json
from typing import Any

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
        # Redact any string values that may contain secrets.
        data = safe.get("data")
        if isinstance(data, str):
            safe["data"] = redact(data)
        elif isinstance(data, dict):
            safe["data"] = {k: (redact(v) if isinstance(v, str) else v) for k, v in data.items()}
        return safe

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
