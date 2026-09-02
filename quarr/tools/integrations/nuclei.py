"""nuclei.py - Real Nuclei integration (Phase 2)."""

from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_url
from quarr.tools.integrations.base import ToolIntegration
from quarr.tools.parsers.nuclei import parse_nuclei_jsonl


class NucleiIntegration(ToolIntegration):
    binary_name = "nuclei"
    name = "nuclei"
    category = "network"
    risk_level = RiskLevel.MEDIUM
    default_timeout = 600
    requires_scope = True

    def build_command(self, *, target: str, **kwargs) -> list[str]:
        url = validate_url(target)
        return ["nuclei", "-u", url, "-jsonl", "-silent"]

    def parse_output(self, raw: str) -> dict[str, Any]:
        return parse_nuclei_jsonl(raw)
