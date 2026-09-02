"""
app.py - FastAPI web backend (Phase 6, optional).

Thin REST layer over the existing core modules (persistence, reporter, agent).
- Lists engagements, returns state/findings (secrets redacted).
- Runs an agent query (authorization-gated via the engagement policy).
- Generates reports.
- Exposes a WebSocket channel for real-time events.

Serves the static dashboard from quarr/ui/ if present.
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from quarr.api.websocket import manager
from quarr.core import persistence
from quarr.core.logging import get_logger
from quarr.core.reporter import generate_executive_summary, generate_technical_report
from quarr.core.secrets import redact

logger = get_logger("quarr.api")

app = FastAPI(title="QUARR API", version="1.0")

# Agent factory is injectable for testing (returns an object with async run()).
_agent_factory = None


def set_agent_factory(factory) -> None:
    global _agent_factory
    _agent_factory = factory


def _redact_obj(obj):
    """Recursively redact string values in a JSON-serializable object."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj


class QueryRequest(BaseModel):
    query: str


class ReportRequest(BaseModel):
    type: str = "executive"


@app.get("/engagements")
def list_engagements():
    return {"engagements": persistence.list_engagements()}


@app.get("/engagements/{engagement_id}/state")
def get_state(engagement_id: str):
    state = persistence.load_state(engagement_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return _redact_obj(state.model_dump(mode="json"))


@app.get("/engagements/{engagement_id}/findings")
def get_findings(engagement_id: str):
    state = persistence.load_state(engagement_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "status": f.status.value,
            "confidence": f.confidence,
            "asset": f.asset,
        }
        for f in state.findings
    ]
    return {"findings": _redact_obj(findings)}


@app.post("/engagements/{engagement_id}/query")
async def run_query(engagement_id: str, req: QueryRequest):
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=422, detail="Empty query")
    state = persistence.load_state(engagement_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if _agent_factory is None:
        raise HTTPException(status_code=503, detail="Agent backend not configured")

    agent = _agent_factory(state.engagement)
    result = await agent.run(req.query, status_callback=manager.make_status_callback())
    return {"result": redact(str(result))}


@app.post("/engagements/{engagement_id}/report")
def make_report(engagement_id: str, req: ReportRequest):
    state = persistence.load_state(engagement_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if req.type == "technical":
        content = generate_technical_report(state)
    else:
        content = generate_executive_summary(state)
    return {"type": req.type, "content": redact(content)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # Send an initial event so clients can confirm the channel is live.
    await websocket.send_json({"type": "connected", "data": "ok"})
    try:
        while True:
            await websocket.receive_text()  # keep-alive; ignore client messages
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# --- Static dashboard ---

_UI_DIR = Path(__file__).resolve().parent.parent / "ui"


@app.get("/", response_class=HTMLResponse)
def dashboard():
    index = _UI_DIR / "index.html"
    if index.exists():
        return index.read_text()
    return "<h1>QUARR API</h1><p>Dashboard not installed. See /docs.</p>"
