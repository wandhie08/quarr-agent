"""whatweb.py - WhatWeb fingerprinting integration (Phase 2)."""

import json
from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_url
from quarr.tools.integrations.base import ToolIntegration


class WhatWebIntegration(ToolIntegration):
    binary_name = "whatweb"
    name = "whatweb"
    category = "web"
    risk_level = RiskLevel.LOW
    default_timeout = 120
    requires_scope = True

    def build_command(self, *, target: str, **kwargs) -> list[str]:
        url = validate_url(target)
        return ["whatweb", "--log-json=-", "--no-errors", url]

    def parse_output(self, raw: str) -> dict[str, Any]:
        technologies = []
        target = None
        for line in (raw or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            target = obj.get("target", target)
            plugins = obj.get("plugins", {})
            technologies.extend(plugins.keys())
        return {"target": target, "technologies": sorted(set(technologies))}
