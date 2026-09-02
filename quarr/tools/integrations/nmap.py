"""nmap.py - Real Nmap integration (Phase 2)."""

from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_ports, validate_target
from quarr.tools.integrations.base import ToolIntegration
from quarr.tools.parsers.nmap import parse_nmap_xml


class NmapIntegration(ToolIntegration):
    binary_name = "nmap"
    name = "nmap"
    category = "network"
    risk_level = RiskLevel.MEDIUM
    default_timeout = 300
    requires_scope = True

    def __init__(self, mode: str = "service", executor=None):
        super().__init__(executor=executor)
        self.mode = mode  # "discovery" | "service"

    def build_command(self, *, target: str, ports: str | None = None, **kwargs) -> list[str]:
        target = validate_target(target)
        argv = ["nmap"]
        if self.mode == "discovery":
            argv.append("-sn")
        else:
            argv.append("-sV")
            if ports:
                argv += ["-p", validate_ports(ports)]
        argv += ["-oX", "-", target]
        return argv

    def parse_output(self, raw: str) -> dict[str, Any]:
        return parse_nmap_xml(raw)
