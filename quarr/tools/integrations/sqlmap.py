"""sqlmap.py - Real SQLMap integration (Phase 2).

Always runs non-interactively (--batch). Level/risk are capped to safe defaults
unless an explicit override is provided.
"""

from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_url
from quarr.tools.integrations.base import ToolIntegration


class SqlmapIntegration(ToolIntegration):
    binary_name = "sqlmap"
    name = "sqlmap"
    category = "web"
    risk_level = RiskLevel.HIGH
    default_timeout = 900
    requires_scope = True

    def build_command(self, *, target: str, level: int = 1, risk: int = 1, **kwargs) -> list[str]:
        url = validate_url(target)
        # Clamp to safe bounds.
        level = max(1, min(int(level), 5))
        risk = max(1, min(int(risk), 3))
        return [
            "sqlmap",
            "-u",
            url,
            "--batch",
            "--level",
            str(level),
            "--risk",
            str(risk),
        ]

    def parse_output(self, raw: str) -> dict[str, Any]:
        text = raw or ""
        injectable = "is vulnerable" in text.lower() or "sqlmap identified" in text.lower()
        findings = []
        if injectable:
            findings.append(
                {
                    "title": "SQL Injection detected",
                    "severity": "high",
                    "tool": "sqlmap",
                }
            )
        return {"injectable": injectable, "findings": findings}
