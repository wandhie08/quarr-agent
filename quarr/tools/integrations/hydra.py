"""hydra.py - Hydra online brute-force integration (Phase 2).

HIGH risk. Wordlist paths are validated against an allowlist and any cracked
credentials are redacted in the result summary.
"""

import re
from typing import Any

from quarr.core.models import RiskLevel
from quarr.tools.integrations import _validate
from quarr.tools.integrations._validate import redact_secrets, validate_target
from quarr.tools.integrations.base import ToolIntegration


class HydraIntegration(ToolIntegration):
    binary_name = "hydra"
    name = "hydra"
    category = "credentials"
    risk_level = RiskLevel.HIGH
    default_timeout = 900
    requires_scope = True

    def build_command(
        self,
        *,
        target: str,
        service: str = "ssh",
        userlist: str = None,
        passlist: str = None,
        **kwargs,
    ) -> list[str]:
        host = validate_target(target)
        service = re.sub(r"[^a-z0-9]", "", service.lower())
        argv = ["hydra"]
        if userlist:
            argv += ["-L", _validate.validate_file_path(userlist)]
        if passlist:
            argv += ["-P", _validate.validate_file_path(passlist)]
        argv += [host, service]
        return argv

    def parse_output(self, raw: str) -> dict[str, Any]:
        text = raw or ""
        # Count valid credentials without exposing them.
        count = len(re.findall(r"login:\s*\S+\s+password:\s*\S+", text))
        return {
            "credentials_found": count,
            "summary": redact_secrets(text)[:500],
        }
