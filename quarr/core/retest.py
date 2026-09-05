"""
retest.py - M18: Retesting Engine

Re-test findings after remediation to verify fixes.
Tracks retest history and status changes.
"""

import logging
from datetime import datetime

from quarr.core.models import Finding, FindingStatus, PentestState

logger = logging.getLogger("quarr.retest")


def get_retestable_findings(state: PentestState) -> list[Finding]:
    """Get findings that can be retested (confirmed or reported)."""
    return [
        f for f in state.findings
        if f.status in (FindingStatus.CONFIRMED, FindingStatus.REPORTED)
    ]


def suggest_retest_tools(finding: Finding) -> list[dict]:
    """Suggest which tools to use for retesting a finding."""
    title_lower = finding.title.lower()

    suggestions = []

    if "sql injection" in title_lower or "sqli" in title_lower:
        suggestions.append({"tool": "sqli_scan", "args": {"target": finding.asset}})
    if "xss" in title_lower or "cross-site" in title_lower:
        suggestions.append({"tool": "xss_scan", "args": {"target": finding.asset}})
    if "command injection" in title_lower:
        suggestions.append({"tool": "command_injection_scan", "args": {"target": finding.asset}})
    if "credential" in title_lower or "brute" in title_lower or "password" in title_lower:
        suggestions.append({"tool": "bruteforce_login", "args": {"target": finding.asset, "service": "ssh"}})
    if "ssl" in title_lower or "tls" in title_lower or "certificate" in title_lower:
        suggestions.append({"tool": "ssl_scan", "args": {"target": finding.asset}})
    if "smb" in title_lower:
        suggestions.append({"tool": "smb_enum", "args": {"target": finding.asset}})
    if "manifest" in title_lower or "android" in title_lower or "debuggable" in title_lower or "backup" in title_lower:
        suggestions.append({"tool": "apk_manifest_analysis", "args": {"apk_decoded_dir": finding.asset}})
    if "secret" in title_lower or "hardcoded" in title_lower or "api key" in title_lower:
        suggestions.append({"tool": "apk_secrets_scan", "args": {"directory": finding.asset}})
    if "storage" in title_lower or "plaintext" in title_lower:
        suggestions.append({"tool": "adb_storage_check", "args": {"package": finding.asset}})

    # Fallback: vulnerability scan
    if not suggestions:
        suggestions.append({"tool": "vulnerability_scan", "args": {"target": finding.asset}})

    return suggestions


def mark_retest_result(
    finding: Finding,
    still_vulnerable: bool,
    evidence: str = "",
) -> str:
    """Record retest result on a finding."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    if still_vulnerable:
        finding.evidence.append(f"[RETEST {timestamp}] Still vulnerable: {evidence}")
        return f"Finding {finding.id} retested — STILL VULNERABLE"
    else:
        finding.status = FindingStatus.DISMISSED
        finding.confidence = 0.1
        finding.evidence.append(f"[RETEST {timestamp}] Fixed/remediated: {evidence}")
        return f"Finding {finding.id} retested — REMEDIATED (dismissed)"


def retest_summary(state: PentestState) -> str:
    """Summary of retest status."""
    retestable = get_retestable_findings(state)
    retested = [f for f in state.findings if any("[RETEST" in e for e in f.evidence)]
    fixed = [f for f in retested if f.status == FindingStatus.DISMISSED]
    still_vuln = [f for f in retested if f.status != FindingStatus.DISMISSED]

    lines = [
        "📋 RETEST STATUS",
        f"Findings needing retest: {len(retestable)}",
        f"Already retested: {len(retested)}",
        f"  Fixed: {len(fixed)}",
        f"  Still vulnerable: {len(still_vuln)}",
    ]

    if retestable:
        lines.append("\nAwaiting retest:")
        for f in retestable:
            if not any("[RETEST" in e for e in f.evidence):
                lines.append(f"  [{f.severity.value.upper()}] {f.title} — {f.asset}")

    return "\n".join(lines)
