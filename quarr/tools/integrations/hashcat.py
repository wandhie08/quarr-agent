"""hashcat.py - Hashcat password cracking integration (Phase 2)."""

import re
from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations import _validate
from quarr.tools.integrations._validate import redact_secrets
from quarr.tools.integrations.base import ToolIntegration


class HashcatIntegration(ToolIntegration):
    binary_name = "hashcat"
    name = "hashcat"
    category = "credentials"
    risk_level = RiskLevel.CRITICAL
    default_timeout = 1800
    requires_scope = True

    def build_command(
        self, *, hashfile: str, wordlist: str, mode: str = "0", **kwargs
    ) -> list[str]:
        hf = _validate.validate_file_path(hashfile)
        wl = _validate.validate_file_path(wordlist)
        mode = re.sub(r"[^0-9]", "", str(mode)) or "0"
        return ["hashcat", "-m", mode, "-a", "0", hf, wl, "--quiet"]

    def parse_output(self, raw: str) -> dict[str, Any]:
        text = raw or ""
        # hashcat cracked lines look like hash:plaintext — count, don't expose.
        cracked = len([ln for ln in text.splitlines() if ":" in ln and ln.strip()])
        status = "Cracked" if "Status.........: Cracked" in text or cracked else "Running"
        return {
            "cracked_count": cracked,
            "status": status,
            "summary": redact_secrets("[hashcat output redacted]"),
        }
