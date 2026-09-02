"""dirsearch.py - Directory brute-force integration (Phase 2)."""

import re
from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations._validate import validate_url
from quarr.tools.integrations.base import ToolIntegration


class DirsearchIntegration(ToolIntegration):
    binary_name = "dirsearch"
    name = "dirsearch"
    category = "web"
    risk_level = RiskLevel.MEDIUM
    default_timeout = 600
    requires_scope = True

    def build_command(self, *, target: str, **kwargs) -> list[str]:
        url = validate_url(target)
        return ["dirsearch", "-u", url, "-q", "--format=plain"]

    def parse_output(self, raw: str) -> dict[str, Any]:
        paths = []
        for line in (raw or "").splitlines():
            # Lines like: 200   1KB   http://target/admin/
            m = re.search(r"\b(\d{3})\b.*?(https?://\S+|/\S+)", line)
            if m and m.group(1).startswith(("2", "3")):
                paths.append({"status": int(m.group(1)), "path": m.group(2)})
        return {"paths": paths}
