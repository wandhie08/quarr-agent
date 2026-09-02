"""john.py - John the Ripper password cracking integration (Phase 2)."""

import re
from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations import _validate
from quarr.tools.integrations.base import ToolIntegration


class JohnIntegration(ToolIntegration):
    binary_name = "john"
    name = "john"
    category = "credentials"
    risk_level = RiskLevel.CRITICAL
    default_timeout = 1800
    requires_scope = True

    def build_command(self, *, hashfile: str, wordlist: str, **kwargs) -> list[str]:
        hf = _validate.validate_file_path(hashfile)
        wl = _validate.validate_file_path(wordlist)
        return ["john", f"--wordlist={wl}", hf]

    def parse_output(self, raw: str) -> dict[str, Any]:
        text = raw or ""
        m = re.search(r"(\d+)\s+password hash(?:es)?\s+cracked", text)
        cracked = int(m.group(1)) if m else 0
        return {
            "cracked_count": cracked,
            "summary": "[john output redacted]",
        }
