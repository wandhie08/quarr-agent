"""
permissions.py - Role-based tool permissions (Phase 4).

Maps each tool's risk level to a minimum required role and checks the current
session role against it.
"""

from quarr.core.exceptions import PolicyViolationError
from quarr.core.models import RiskLevel

ROLE_ORDER = {"viewer": 0, "operator": 1, "admin": 2}

RISK_MIN_ROLE = {
    RiskLevel.LOW: "viewer",
    RiskLevel.MEDIUM: "operator",
    RiskLevel.HIGH: "operator",
    RiskLevel.CRITICAL: "admin",
}


def check(role: str, risk: RiskLevel, tool_name: str = "") -> None:
    role = (role or "operator").lower()
    if role not in ROLE_ORDER:
        raise PolicyViolationError("Unknown role", context={"role": role})
    required = RISK_MIN_ROLE.get(risk, "admin")
    if ROLE_ORDER[role] < ROLE_ORDER[required]:
        raise PolicyViolationError(
            "Insufficient role for tool risk level",
            context={
                "tool": tool_name,
                "role": role,
                "required_role": required,
                "risk": risk.value,
            },
        )
