"""
notifications.py - Slack/Discord notifications (Phase 5).

Sends alerts when a finding reaches CONFIRMED at HIGH/CRITICAL severity.
Disabled by default; failures are logged and never crash the agent. Content is
redacted via the Phase 4 secrets manager.
"""

import httpx

from quarr.core.logging import get_logger
from quarr.core.models import FindingStatus, Severity
from quarr.core.secrets import redact

logger = get_logger("quarr.notifications")

_SEV_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Notifier:
    def __init__(
        self,
        slack_url: str = "",
        discord_url: str = "",
        threshold: Severity = Severity.HIGH,
        enabled: bool = False,
    ):
        self.slack_url = slack_url
        self.discord_url = discord_url
        self.threshold = threshold
        # Only active when explicitly enabled AND a webhook is configured.
        self.enabled = enabled and bool(slack_url or discord_url)

    def _should_notify(self, finding) -> bool:
        if not self.enabled:
            return False
        if finding.status not in (FindingStatus.CONFIRMED, FindingStatus.REPORTED):
            return False
        return _SEV_ORDER.get(finding.severity, 0) >= _SEV_ORDER.get(self.threshold, 3)

    def _format(self, finding) -> str:
        return redact(f"[{finding.severity.value.upper()}] {finding.title} on {finding.asset}")

    def notify_finding(self, finding) -> bool:
        if not self._should_notify(finding):
            return False
        message = self._format(finding)
        sent = False
        for url, payload in (
            (self.slack_url, {"text": message}),
            (self.discord_url, {"content": message}),
        ):
            if not url:
                continue
            try:
                httpx.post(url, json=payload, timeout=10)
                sent = True
            except Exception as e:  # never crash the agent
                logger.warning("notify_failed", error=str(e))
        return sent
