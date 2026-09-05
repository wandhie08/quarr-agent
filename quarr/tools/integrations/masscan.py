"""masscan.py - Real Masscan integration (Phase 2)."""

import json
from typing import Any

from quarr.core.exceptions import ToolOutputParseError
from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_ports, validate_target
from quarr.tools.integrations.base import ToolIntegration


class MasscanIntegration(ToolIntegration):
    binary_name = "masscan"
    name = "masscan"
    category = "network"
    risk_level = RiskLevel.HIGH  # fast/aggressive scanning
    default_timeout = 300
    requires_scope = True

    def build_command(
        self, *, target: str, ports: str = "1-1000", rate: str = "1000", **kwargs
    ) -> list[str]:
        host = validate_target(target)
        port_spec = validate_ports(ports)
        rate = validate_ports(rate)  # numeric-only check
        return ["masscan", host, "-p", port_spec, "--rate", rate, "-oJ", "-"]

    def parse_output(self, raw: str) -> dict[str, Any]:
        if raw is None:
            raise ToolOutputParseError("Masscan output is None")
        text = raw.strip()
        if not text:
            return {"services": []}
        # masscan -oJ emits a JSON array (sometimes with a trailing comma).
        text = text.rstrip(",")
        if not text.startswith("["):
            text = f"[{text}]"
        try:
            records = json.loads(text)
        except json.JSONDecodeError as e:
            raise ToolOutputParseError("Malformed masscan JSON", context={"error": str(e)}) from e
        services = []
        for rec in records:
            if not isinstance(rec, dict):
                continue  # skip non-object elements instead of crashing
            ip = rec.get("ip")
            for p in rec.get("ports", []):
                if not isinstance(p, dict):
                    continue
                services.append(
                    {
                        "host": ip,
                        "port": p.get("port"),
                        "protocol": p.get("proto", "tcp"),
                        "state": p.get("status", "open"),
                    }
                )
        return {"services": services}
