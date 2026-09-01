"""
reporter.py - M7: Assessment Report Generator

Generates:
1. Executive Summary (non-teknis, untuk management)
2. Technical Report (detail findings, evidence, remediation)
3. Markdown export
4. JSON export

Report mengikuti format standar:
- OWASP-style findings
- CVSS v3.1 scoring
- CWE mapping
- Evidence-based
"""

import json
from datetime import datetime
from typing import Optional

from quarr.core.models import PentestState, Finding, FindingStatus, Severity
from quarr.knowledge.base import get_cwe_for_finding, get_cvss_range, CWE_DATABASE, CVSS_REFERENCE


# === Severity Stats ===

def _count_by_severity(state: PentestState) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in state.findings:
        sev = f.severity.value
        if sev in counts:
            counts[sev] += 1
    return counts


def _risk_rating(counts: dict) -> str:
    if counts["critical"] > 0:
        return "CRITICAL"
    if counts["high"] > 0:
        return "HIGH"
    if counts["medium"] > 0:
        return "MEDIUM"
    if counts["low"] > 0:
        return "LOW"
    return "INFORMATIONAL"


# ============================================================
# Executive Summary
# ============================================================

def generate_executive_summary(state: PentestState) -> str:
    """Generate non-technical executive summary."""
    eng = state.engagement
    counts = _count_by_severity(state)
    risk = _risk_rating(counts)
    total_findings = sum(counts.values())
    confirmed = len([f for f in state.findings if f.status in (FindingStatus.CONFIRMED, FindingStatus.REPORTED)])

    lines = [
        "# EXECUTIVE SUMMARY",
        f"## {eng.name}",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d')}",
        f"**Scope:** {', '.join(eng.allowed_targets)}",
        f"**Overall Risk Rating:** {risk}",
        "",
        "---",
        "",
        "## Overview",
        "",
        f"A security assessment was conducted on the defined scope. "
        f"The assessment discovered **{len(state.hosts)} host(s)** with "
        f"**{sum(len(h.services) for h in state.hosts)} service(s)**. "
        f"A total of **{total_findings} security finding(s)** were identified, "
        f"of which **{confirmed}** have been confirmed through validation.",
        "",
        "## Risk Summary",
        "",
        "| Severity | Count |",
        "| -------- | ----- |",
    ]

    for sev in ["critical", "high", "medium", "low", "info"]:
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
        lines.append(f"| {emoji} {sev.upper()} | {counts[sev]} |")

    lines.extend([
        "",
        "## Key Findings",
        "",
    ])

    # Top findings by severity
    sorted_findings = sorted(
        state.findings,
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
    )

    for i, f in enumerate(sorted_findings[:5], 1):
        status_str = f.status.value.upper()
        lines.append(f"{i}. **[{f.severity.value.upper()}]** {f.title} — {f.asset} ({status_str})")

    if not sorted_findings:
        lines.append("No security findings were identified during this assessment.")

    lines.extend([
        "",
        "## Recommendations",
        "",
        "The following actions are recommended in order of priority:",
        "",
    ])

    priority = 1
    for f in sorted_findings:
        if f.remediation:
            lines.append(f"{priority}. {f.remediation}")
            priority += 1
        if priority > 5:
            break

    if priority == 1:
        lines.append("- Continue monitoring and maintain security best practices.")

    return "\n".join(lines)


# ============================================================
# Technical Report
# ============================================================

def generate_technical_report(state: PentestState) -> str:
    """Generate detailed technical report with all findings."""
    eng = state.engagement
    counts = _count_by_severity(state)
    risk = _risk_rating(counts)

    lines = [
        "# TECHNICAL SECURITY ASSESSMENT REPORT",
        "",
        f"**Engagement:** {eng.name}",
        f"**Engagement ID:** {eng.id}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Scope:** {', '.join(eng.allowed_targets)}",
    ]
    if eng.excluded_targets:
        lines.append(f"**Excluded:** {', '.join(eng.excluded_targets)}")
    lines.extend([
        f"**Overall Risk:** {risk}",
        "",
        "---",
        "",
        "## 1. Scope & Methodology",
        "",
        f"The assessment targeted {len(eng.allowed_targets)} scope entry/entries. "
        f"A total of {len(state.tool_history)} tool executions were performed across "
        f"reconnaissance, discovery, vulnerability scanning, and exploitation phases.",
        "",
        f"**Tools executed:** {len(state.tool_history)}",
        f"**Hosts discovered:** {len(state.hosts)}",
        f"**Observations recorded:** {len(state.observations)}",
        "",
    ])

    # === Hosts & Services ===
    lines.extend([
        "## 2. Asset Inventory",
        "",
        "| Host | Hostname | OS | Services |",
        "| ---- | -------- | -- | -------- |",
    ])

    for h in state.hosts:
        svc_str = ", ".join(
            f"{s.port}/{s.protocol} {s.name or '?'}"
            + (f" ({s.version})" if s.version else "")
            for s in h.services
        ) or "None enumerated"
        lines.append(
            f"| {h.address} | {h.hostname or '-'} | {h.os or '-'} | {svc_str} |"
        )

    if not state.hosts:
        lines.append("| - | - | - | No hosts discovered |")

    # === Findings ===
    lines.extend([
        "",
        "## 3. Findings",
        "",
    ])

    sorted_findings = sorted(
        state.findings,
        key=lambda f: ["critical", "high", "medium", "low", "info"].index(f.severity.value)
    )

    if not sorted_findings:
        lines.append("No security findings were identified during this assessment.")

    for i, f in enumerate(sorted_findings, 1):
        cwe = get_cwe_for_finding(f.title)
        cvss_info = get_cvss_range(f.severity.value)

        lines.extend([
            f"### 3.{i} {f.title}",
            "",
            f"| Field | Value |",
            f"| ----- | ----- |",
            f"| **ID** | {f.id} |",
            f"| **Severity** | {f.severity.value.upper()} |",
            f"| **CVSS Range** | {cvss_info} |",
            f"| **Status** | {f.status.value.upper()} |",
            f"| **Confidence** | {f.confidence:.0%} |",
            f"| **Asset** | {f.asset} |",
        ])
        if cwe:
            lines.append(f"| **CWE** | {cwe['id']}: {cwe['name']} |")
        if f.references:
            lines.append(f"| **References** | {', '.join(f.references)} |")

        lines.append("")

        if f.description:
            lines.extend([
                "**Description:**",
                "",
                f"{f.description}",
                "",
            ])

        if f.evidence:
            lines.extend([
                "**Evidence:**",
                "",
            ])
            for j, ev in enumerate(f.evidence, 1):
                lines.append(f"{j}. {ev}")
            lines.append("")

        if f.impact:
            lines.extend([
                "**Impact:**",
                "",
                f"{f.impact}",
                "",
            ])

        if f.remediation:
            lines.extend([
                "**Remediation:**",
                "",
                f"{f.remediation}",
                "",
            ])
        elif cwe:
            lines.extend([
                "**Remediation:**",
                "",
                f"{cwe['remediation']}",
                "",
            ])

        lines.append("---")
        lines.append("")

    # === Tool Execution Log ===
    lines.extend([
        "## 4. Tool Execution Log",
        "",
        "| # | Tool | Arguments | Result | Time |",
        "| - | ---- | --------- | ------ | ---- |",
    ])

    for i, t in enumerate(state.tool_history, 1):
        args_str = ", ".join(f"{k}={v}" for k, v in t.arguments.items())
        status = "✅" if t.success else "❌"
        time_str = t.timestamp.strftime("%H:%M:%S")
        lines.append(f"| {i} | {t.tool_name} | {args_str} | {status} | {time_str} |")

    if not state.tool_history:
        lines.append("| - | - | - | - | - |")

    # === Observations ===
    lines.extend([
        "",
        "## 5. Observations",
        "",
    ])

    for obs in state.observations:
        lines.append(f"- **[{obs.source_tool}]** {obs.description}")

    if not state.observations:
        lines.append("- No observations recorded.")

    return "\n".join(lines)


# ============================================================
# Export Functions
# ============================================================

def export_markdown(state: PentestState, filepath: str, report_type: str = "technical") -> str:
    """Export report sebagai markdown file."""
    if report_type == "executive":
        content = generate_executive_summary(state)
    else:
        content = generate_technical_report(state)

    with open(filepath, "w") as f:
        f.write(content)

    return filepath


def export_json(state: PentestState, filepath: str) -> str:
    """Export findings sebagai JSON."""
    data = {
        "engagement": {
            "name": state.engagement.name,
            "id": state.engagement.id,
            "scope": state.engagement.allowed_targets,
            "date": datetime.now().isoformat(),
        },
        "summary": {
            "hosts": len(state.hosts),
            "services": sum(len(h.services) for h in state.hosts),
            "findings": len(state.findings),
            "tool_executions": len(state.tool_history),
            "severity_counts": _count_by_severity(state),
            "risk_rating": _risk_rating(_count_by_severity(state)),
        },
        "hosts": [
            {
                "address": h.address,
                "hostname": h.hostname,
                "os": h.os,
                "services": [
                    {"port": s.port, "protocol": s.protocol, "name": s.name, "version": s.version}
                    for s in h.services
                ]
            }
            for h in state.hosts
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "status": f.status.value,
                "asset": f.asset,
                "description": f.description,
                "evidence": f.evidence,
                "impact": f.impact,
                "remediation": f.remediation,
                "references": f.references,
                "cwe": get_cwe_for_finding(f.title)["id"] if get_cwe_for_finding(f.title) else None,
            }
            for f in state.findings
        ],
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return filepath
