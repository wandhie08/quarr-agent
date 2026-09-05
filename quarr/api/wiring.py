"""
wiring.py - Connect the Web API to a real QuarrAgent (Phase 6 professional).

Sets the REST and Live Console agent factories to construct real QuarrAgent
instances, wired with the shared AuditLogger and (for the live console) the
WebSocket approval gate. Called from app startup.
"""

from quarr.core.agent import QuarrAgent
from quarr.core.audit import AuditLogger
from quarr.core.config import Settings
from quarr.core.logging import get_logger

logger = get_logger("quarr.api.wiring")


def wire_agents(settings: Settings | None = None) -> None:
    """Install real-agent factories for both the REST /query and the Live Console."""
    settings = settings or Settings()
    audit = AuditLogger(
        path=settings.audit_log_path,
        rotate_max_bytes=settings.audit_max_bytes,
        rotate_backups=settings.audit_backups,
    )
    backend = settings.resolved_backend()
    model = settings.openai_model if backend == "openai" else settings.ollama_model
    api_key = settings.openai_api_key if backend == "openai" else None

    def rest_factory(engagement):
        return QuarrAgent(
            model=model, engagement=engagement, api_key=api_key,
            backend=backend, audit_logger=audit,
            session_role=settings.session_role,
        )

    def live_factory(engagement, approval):
        # approval is a WSApproval; its gate_async is the async approval gate.
        return QuarrAgent(
            model=model, engagement=engagement, api_key=api_key,
            backend=backend, audit_logger=audit,
            approval_gate=approval.gate_async,
            session_role=getattr(approval, "role", settings.session_role),
        )

    from quarr.api.app import set_agent_factory
    from quarr.api.live import set_live_agent_factory

    set_agent_factory(rest_factory)
    set_live_agent_factory(live_factory)
    logger.info("agents_wired", backend=backend, model=model)
