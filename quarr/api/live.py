"""
live.py - Live Console WebSocket (Phase 6 professional).

Authenticated WebSocket that runs the agent for an engagement and streams
progress events to the client. Dangerous-tool approval is negotiated over the
same socket: the server sends an "approval_request" and waits for the client's
"approval_response" before the tool runs.

Protocol (JSON messages):
  client → server:
    {"type": "run", "query": "..."}          start an agent run
    {"type": "approval_response", "approved": true}
  server → client:
    {"type": "connected"}
    {"type": "status", "data": "..."}         live status updates
    {"type": "approval_request", "tool": "...", "target": "...", "risk": "..."}
    {"type": "result", "data": "..."}          final agent result (redacted)
    {"type": "error", "data": "..."}
"""

import asyncio

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from quarr.api import security as sec
from quarr.api.auth import AuthError
from quarr.core.logging import get_logger
from quarr.core.secrets import redact

logger = get_logger("quarr.api.live")

# Injectable agent factory (set by app wiring / tests).
_agent_factory = None


def set_live_agent_factory(factory) -> None:
    global _agent_factory
    _agent_factory = factory


def get_live_agent_factory():
    return _agent_factory


class WSApproval:
    """Approval gate that asks the client over the WebSocket."""

    def __init__(self, websocket: WebSocket, role: str, timeout: float = 120.0):
        self.ws = websocket
        self.role = role
        self.timeout = timeout

    async def gate_async(self, tool_name: str, target, risk) -> None:
        from quarr.core.exceptions import PolicyViolationError
        from quarr.core.models import RiskLevel

        if risk not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            return
        await self.ws.send_json({
            "type": "approval_request",
            "tool": tool_name,
            "target": str(target) if target else None,
            "risk": risk.value,
        })
        try:
            raw = await asyncio.wait_for(self.ws.receive_json(), timeout=self.timeout)
        except (TimeoutError, WebSocketDisconnect) as e:
            raise PolicyViolationError(
                "Approval timed out or client disconnected",
                context={"tool": tool_name},
            ) from e
        if not (isinstance(raw, dict) and raw.get("approved") is True):
            raise PolicyViolationError(
                "Dangerous tool denied by operator",
                context={"tool": tool_name, "decision": "denied"},
            )


def _authenticate(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        payload = sec.token_service().decode(token, expected_type="access")
    except AuthError:
        return None
    return {"username": payload["sub"], "role": payload["role"]}


async def live_console_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint: /ws/live?token=<access>&engagement=<id>"""
    token = websocket.query_params.get("token")
    engagement_id = websocket.query_params.get("engagement")
    user = _authenticate(token)

    await websocket.accept()

    if user is None:
        await websocket.send_json({"type": "error", "data": "unauthorized"})
        await websocket.close(code=4401)
        return

    # Only operator/admin may run the live console (execute tools).
    if user["role"] not in ("operator", "admin"):
        await websocket.send_json({"type": "error", "data": "forbidden: operator role required"})
        await websocket.close(code=4403)
        return

    from quarr.core import persistence

    state = persistence.load_state(engagement_id) if engagement_id else None
    if state is None:
        await websocket.send_json({"type": "error", "data": "engagement not found"})
        await websocket.close(code=4404)
        return

    if _agent_factory is None:
        await websocket.send_json({"type": "error", "data": "agent backend not configured"})
        await websocket.close(code=1011)
        return

    await websocket.send_json({"type": "connected", "data": "ok"})

    async def status_cb(message: str) -> None:
        await websocket.send_json({"type": "status", "data": redact(str(message))})

    try:
        while True:
            msg = await websocket.receive_json()
            if not isinstance(msg, dict):
                continue
            if msg.get("type") == "run":
                query = str(msg.get("query", "")).strip()
                if not query:
                    await websocket.send_json({"type": "error", "data": "empty query"})
                    continue
                agent = _agent_factory(state.engagement, WSApproval(websocket, user["role"]))
                try:
                    result = await agent.run(query, status_callback=status_cb)
                    persistence.save_state(agent.state)
                    await websocket.send_json({"type": "result", "data": redact(str(result))})
                except Exception as e:  # surface agent errors, keep socket open
                    await websocket.send_json({"type": "error", "data": redact(str(e))})
            elif msg.get("type") == "close":
                break
    except WebSocketDisconnect:
        logger.info("live_ws_disconnected", engagement=engagement_id)
    except Exception as e:
        logger.error("live_ws_error", error=str(e))
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
