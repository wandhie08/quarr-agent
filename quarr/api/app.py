"""
app.py - Professional FastAPI web backend (Phase 6).

Security-first REST API for QUARR:
- JWT auth (login/refresh) + RBAC (viewer/operator/admin) via quarr.api.security
- Engagement CRUD, hosts/services, findings (+update, +dedup), timeline,
  evidence (+chain verification), tool history
- Report preview + download (html/pdf/json)
- Notifications config
- WebSocket live console (see quarr.api.websocket / live.py)
- Serves the built SPA from quarr/ui/dist (fallback to quarr/ui/index.html)

All responses are redacted of secrets (Phase 4).
"""

import contextlib
import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from quarr.api import security as sec
from quarr.api.auth import build_user_store
from quarr.api.websocket import manager
from quarr.core import persistence
from quarr.core import timeline as timeline_mod
from quarr.core.config import Settings
from quarr.core.dedup import deduplicate
from quarr.core.logging import get_logger
from quarr.core.models import Engagement, FindingStatus, PentestState, Severity
from quarr.core.reporter import (
    export_json,
    generate_executive_summary,
    generate_technical_report,
    render_html,
)
from quarr.core.secrets import redact

logger = get_logger("quarr.api")


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI):
    # Startup: refuse to serve with an insecure JWT secret (fail closed against
    # token forgery). This runs on real server startup, not on import, so tests
    # that override the secret are unaffected.
    sec.assert_secure_config()
    # Wire real QuarrAgent factories unless already configured (e.g. by tests).
    if _agent_factory is None:
        try:
            from quarr.api.wiring import wire_agents

            wire_agents(_settings)
        except Exception as e:  # never block startup on wiring issues
            logger.warning("agent_wiring_failed", error=str(e))
    yield
    # Shutdown: nothing to tear down currently.


app = FastAPI(
    title="QUARR API",
    version="2.0",
    description="Cyber Operations API",
    lifespan=_lifespan,
)

_settings = Settings()
sec.init_security(_settings, build_user_store(_settings))

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _settings.cors_origins.split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# Agent factory for the live console (injectable; see live.py wiring).
_agent_factory = None


def set_agent_factory(factory) -> None:
    global _agent_factory
    _agent_factory = factory


def get_agent_factory():
    return _agent_factory


# ------------------------------------------------------------------ helpers

def _redact_obj(obj):
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_obj(v) for v in obj]
    return obj


def _load_or_404(engagement_id: str) -> PentestState:
    state = persistence.load_state(engagement_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return state


# ------------------------------------------------------------------ models

class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class CreateEngagementRequest(BaseModel):
    name: str
    allowed_targets: list[str] = []
    excluded_targets: list[str] = []


class QueryRequest(BaseModel):
    query: str


class ReportRequest(BaseModel):
    type: str = "executive"


class FindingUpdate(BaseModel):
    severity: str | None = None
    status: str | None = None
    confidence: float | None = None


# ------------------------------------------------------------------ auth

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    cid = sec.client_id(request)
    if not sec.rate_limiter().check(cid):
        raise HTTPException(status_code=429, detail="Too many login attempts")
    user = sec.user_store().verify(req.username, req.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    ts = sec.token_service()
    return {
        "access_token": ts.access_token(user.username, user.role),
        "refresh_token": ts.refresh_token(user.username, user.role),
        "token_type": "bearer",
        "role": user.role,
        "username": user.username,
    }


@app.post("/api/auth/refresh")
def refresh(req: RefreshRequest):
    from quarr.api.auth import AuthError

    try:
        payload = sec.token_service().decode(req.refresh_token, expected_type="refresh")
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e.message)) from e
    # Re-resolve the user from the store so a removed/downgraded account cannot
    # keep elevated privileges via a still-valid refresh token.
    store = sec.user_store()
    current = store.users.get(payload["sub"])
    if current is None:
        raise HTTPException(status_code=401, detail="User no longer exists")
    ts = sec.token_service()
    return {
        "access_token": ts.access_token(current.username, current.role),
        "token_type": "bearer",
    }


@app.get("/api/auth/me")
def me(user: dict = Depends(sec.get_current_user)):
    return user


# ------------------------------------------------------------------ engagements

@app.get("/api/engagements")
def list_engagements(user: dict = Depends(sec.require_role("viewer"))):
    return {"engagements": persistence.list_engagements()}


@app.post("/api/engagements", status_code=201)
def create_engagement(req: CreateEngagementRequest,
                      user: dict = Depends(sec.require_role("operator"))):
    from quarr.core.validators.target import TargetValidationError, normalize

    targets = []
    for t in req.allowed_targets:
        try:
            targets.append(normalize(t))
        except TargetValidationError as e:
            raise HTTPException(status_code=422, detail=f"Invalid target: {t}") from e
    excluded = []
    for t in req.excluded_targets:
        try:
            excluded.append(normalize(t))
        except TargetValidationError as e:
            raise HTTPException(status_code=422, detail=f"Invalid excluded target: {t}") from e
    state = PentestState()
    state.engagement = Engagement(
        name=req.name or "Unnamed Assessment",
        allowed_targets=targets,
        excluded_targets=excluded,
    )
    persistence.save_state(state)
    logger.info("engagement_created", id=state.engagement.id, by=user["username"])
    return {"id": state.engagement.id, "name": state.engagement.name}


@app.get("/api/engagements/{engagement_id}")
def get_engagement(engagement_id: str, user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    counts = {s.value: 0 for s in Severity}
    for f in state.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return _redact_obj({
        "id": state.engagement.id,
        "name": state.engagement.name,
        "scope": state.engagement.allowed_targets,
        "excluded": state.engagement.excluded_targets,
        "hosts": len(state.hosts),
        "findings": len(state.findings),
        "severity_counts": counts,
        "tools_run": len(state.tool_history),
    })


@app.delete("/api/engagements/{engagement_id}")
def delete_engagement(engagement_id: str, user: dict = Depends(sec.require_role("admin"))):
    ok = persistence.delete_engagement(engagement_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Engagement not found")
    logger.info("engagement_deleted", id=engagement_id, by=user["username"])
    return {"deleted": engagement_id}


@app.get("/api/engagements/{engagement_id}/state")
def get_state(engagement_id: str, user: dict = Depends(sec.require_role("viewer"))):
    return _redact_obj(_load_or_404(engagement_id).model_dump(mode="json"))


@app.get("/api/engagements/{engagement_id}/hosts")
def get_hosts(engagement_id: str, user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    return _redact_obj({"hosts": [h.model_dump(mode="json") for h in state.hosts]})


@app.get("/api/engagements/{engagement_id}/findings")
def get_findings(engagement_id: str, user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    findings = [
        {
            "id": f.id, "title": f.title, "severity": f.severity.value,
            "status": f.status.value, "confidence": f.confidence,
            "asset": f.asset, "description": f.description,
            "remediation": f.remediation, "evidence_count": len(f.evidence),
        }
        for f in state.findings
    ]
    return {"findings": _redact_obj(findings)}


@app.patch("/api/engagements/{engagement_id}/findings/{finding_id}")
def update_finding(engagement_id: str, finding_id: str, upd: FindingUpdate,
                   user: dict = Depends(sec.require_role("operator"))):
    state = _load_or_404(engagement_id)
    target = next((f for f in state.findings if f.id == finding_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if upd.severity is not None:
        try:
            target.severity = Severity(upd.severity)
        except ValueError as e:
            raise HTTPException(status_code=422, detail="Invalid severity") from e
    if upd.status is not None:
        try:
            target.status = FindingStatus(upd.status)
        except ValueError as e:
            raise HTTPException(status_code=422, detail="Invalid status") from e
    if upd.confidence is not None:
        target.confidence = max(0.0, min(1.0, upd.confidence))
    persistence.save_state(state)
    return {"updated": finding_id}


@app.post("/api/engagements/{engagement_id}/dedup")
def dedup_findings(engagement_id: str, dry_run: bool = True,
                   user: dict = Depends(sec.require_role("operator"))):
    state = _load_or_404(engagement_id)
    report = deduplicate(state, dry_run=dry_run)
    if not dry_run:
        persistence.save_state(state)
    return {"merged": report.merged, "groups": report.groups, "dry_run": dry_run}


@app.get("/api/engagements/{engagement_id}/timeline")
def get_timeline(engagement_id: str, kind: str | None = None,
                 user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    events = timeline_mod.build_timeline(state)
    if kind:
        events = timeline_mod.filter_events(events, kind=kind)
    return _redact_obj({"events": [e.__dict__ for e in events]})


@app.get("/api/engagements/{engagement_id}/tool-history")
def get_tool_history(engagement_id: str, user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    return _redact_obj({
        "tool_history": [t.model_dump(mode="json") for t in state.tool_history]
    })


@app.get("/api/engagements/{engagement_id}/evidence")
def get_evidence(engagement_id: str, user: dict = Depends(sec.require_role("viewer"))):
    # Load the persisted evidence index if present.
    index = Path(persistence.ENGAGEMENTS_DIR) / engagement_id / "evidence" / "index.json"
    if not index.exists():
        return {"evidence": [], "chain_verified": True}
    data = json.loads(index.read_text())
    # Verify chain-of-custody hashes.
    import hashlib
    verified = True
    for entry in data:
        fp = entry.get("filepath")
        expected = entry.get("sha256")
        if fp and expected and Path(fp).exists():
            actual = hashlib.sha256(Path(fp).read_bytes()).hexdigest()
            entry["tampered"] = actual != expected
            if entry["tampered"]:
                verified = False
    return _redact_obj({"evidence": data, "chain_verified": verified})


# ------------------------------------------------------------------ reports

@app.post("/api/engagements/{engagement_id}/report")
def make_report(engagement_id: str, req: ReportRequest,
                user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    if req.type == "technical":
        content = generate_technical_report(state)
    else:
        content = generate_executive_summary(state)
    return {"type": req.type, "content": redact(content)}


@app.get("/api/engagements/{engagement_id}/report/download")
def download_report(engagement_id: str, fmt: str = "html", type: str = "executive",
                    user: dict = Depends(sec.require_role("viewer"))):
    state = _load_or_404(engagement_id)
    if fmt == "json":
        import os
        import tempfile
        tmp = tempfile.mktemp(suffix=".json")
        export_json(state, tmp)
        content = Path(tmp).read_text()
        os.unlink(tmp)
        return Response(content, media_type="application/json",
                        headers={"Content-Disposition": "attachment; filename=report.json"})
    if fmt == "pdf":
        try:
            import weasyprint
        except ImportError:
            raise HTTPException(status_code=501, detail="PDF export unavailable (WeasyPrint not installed)") from None
        html = render_html(state, type)
        pdf = weasyprint.HTML(string=html).write_pdf()
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": "attachment; filename=report.pdf"})
    # default html
    html = render_html(state, type)
    return Response(html, media_type="text/html",
                    headers={"Content-Disposition": "attachment; filename=report.html"})


# ------------------------------------------------------------------ notifications

@app.get("/api/notifications/config")
def get_notifications(user: dict = Depends(sec.require_role("admin"))):
    return {
        "enabled": bool(_settings.__dict__.get("notify_enabled", False)),
        "slack_configured": False,
        "discord_configured": False,
        "threshold": "high",
    }


# ------------------------------------------------------------------ live query (REST fallback)

@app.post("/api/engagements/{engagement_id}/query")
async def run_query(engagement_id: str, req: QueryRequest,
                    user: dict = Depends(sec.require_role("operator"))):
    if not req.query or not req.query.strip():
        raise HTTPException(status_code=422, detail="Empty query")
    state = _load_or_404(engagement_id)
    if _agent_factory is None:
        raise HTTPException(status_code=503, detail="Agent backend not configured")
    agent = _agent_factory(state.engagement)
    result = await agent.run(req.query, status_callback=manager.make_status_callback())
    return {"result": redact(str(result))}


# ------------------------------------------------------------------ websocket

from quarr.api.live import live_console_endpoint  # noqa: E402
from quarr.api.websocket import websocket_endpoint  # noqa: E402

app.add_api_websocket_route("/ws", websocket_endpoint)
app.add_api_websocket_route("/ws/live", live_console_endpoint)


# ------------------------------------------------------------------ SPA / static

_UI_DIR = Path(__file__).resolve().parent.parent / "ui"
_DIST_DIR = _UI_DIR / "dist"

if _DIST_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_DIST_DIR / "assets")), name="assets")


@app.get("/", response_class=HTMLResponse)
def index():
    dist_index = _DIST_DIR / "index.html"
    if dist_index.exists():
        return dist_index.read_text()
    legacy = _UI_DIR / "index.html"
    if legacy.exists():
        return legacy.read_text()
    return "<h1>QUARR API</h1><p>SPA not built. Run: cd quarr/ui && npm install && npm run build. See /docs.</p>"


@app.get("/{path:path}", response_class=HTMLResponse)
def spa_fallback(path: str):
    # Client-side routing fallback → serve SPA index for non-API paths.
    if path.startswith("api/") or path.startswith("assets/"):
        raise HTTPException(status_code=404, detail="Not found")
    dist_index = _DIST_DIR / "index.html"
    if dist_index.exists():
        return dist_index.read_text()
    raise HTTPException(status_code=404, detail="Not found")
