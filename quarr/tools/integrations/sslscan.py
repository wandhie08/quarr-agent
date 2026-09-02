"""sslscan.py - SSLScan TLS analysis integration (Phase 2)."""

import re
from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_target
from quarr.tools.integrations.base import ToolIntegration


class SSLScanIntegration(ToolIntegration):
    binary_name = "sslscan"
    name = "sslscan"
    category = "web"
    risk_level = RiskLevel.LOW
    default_timeout = 120
    requires_scope = True

    def build_command(self, *, target: str, **kwargs) -> list[str]:
        host = validate_target(target)
        return ["sslscan", "--no-colour", host]

    def parse_output(self, raw: str) -> dict[str, Any]:
        text = raw or ""
        protocols = {}
        for proto in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
            m = re.search(rf"{re.escape(proto)}\s+(enabled|disabled)", text)
            if m:
                protocols[proto] = m.group(1)
        weak = [
            p for p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if protocols.get(p) == "enabled"
        ]
        return {"protocols": protocols, "weak_protocols": weak}
