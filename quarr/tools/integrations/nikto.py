"""nikto.py - Real Nikto integration (Phase 2)."""

from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_target
from quarr.tools.integrations.base import ToolIntegration
from quarr.tools.parsers.nikto import parse_nikto


class NiktoIntegration(ToolIntegration):
    binary_name = "nikto"
    name = "nikto"
    category = "web"
    risk_level = RiskLevel.MEDIUM
    default_timeout = 600
    requires_scope = True

    def build_command(self, *, target: str, **kwargs) -> list[str]:
        host = validate_target(target)
        return ["nikto", "-host", host, "-Format", "json", "-output", "-", "-nointeractive"]

    def parse_output(self, raw: str) -> dict[str, Any]:
        return parse_nikto(raw)
