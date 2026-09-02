"""
approval.py - Approval workflow for dangerous tools (Phase 4).

Requires explicit confirmation before running HIGH/CRITICAL risk tools. In
non-interactive mode, auto_approve can be enabled (defaults to requiring
approval). Decisions are recorded in the audit log when available.
"""

from quarr.core.exceptions import PolicyViolationError
from quarr.core.logging import get_logger
from quarr.core.models import RiskLevel

logger = get_logger("quarr.approval")

DANGEROUS = {RiskLevel.HIGH, RiskLevel.CRITICAL}


class ApprovalWorkflow:
    def __init__(self, auto_approve: bool = False, prompt_fn=None, audit_logger=None):
        self.auto_approve = auto_approve
        self._prompt = prompt_fn or input
        self.audit_logger = audit_logger

    def gate(self, tool_name: str, target, risk: RiskLevel) -> None:
        if risk not in DANGEROUS:
            return

        if self.auto_approve:
            decision = "approved"
        else:
            try:
                answer = self._prompt(
                    f"⚠️  Approve HIGH/CRITICAL tool '{tool_name}' on '{target}'? (y/N): "
                )
            except (EOFError, KeyboardInterrupt):
                answer = "n"
            decision = "approved" if str(answer).strip().lower() in ("y", "yes") else "denied"

        if self.audit_logger:
            try:
                self.audit_logger.record_approval(
                    tool_name=tool_name, target=target, decision=decision
                )
            except Exception:  # audit must never break the gate
                logger.warning("audit_approval_failed", tool=tool_name)

        logger.info("approval_decision", tool=tool_name, decision=decision)

        if decision != "approved":
            raise PolicyViolationError(
                "Dangerous tool execution not approved",
                context={"tool": tool_name, "decision": decision},
            )
