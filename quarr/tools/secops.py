"""
secops_tools.py - M25: Security Operations

Automated security operations:
- Scheduled security health check
- Alert triage
- Compliance reporting
- Security metrics dashboard (text)
- Playbook execution
"""

import os
from datetime import datetime


def _is_active(text: str) -> bool:
    """True if service/firewall status text indicates 'active'.

    Guards against the substring trap where "active" in "inactive" is True —
    which previously reported a disabled firewall/service as active in
    compliance reports.
    """
    t = (text or "").lower()
    return "inactive" not in t and ("active" in t or "chain" in t)

# ============================================================
# Security Health Score
# ============================================================

def security_health_check() -> str:
    """
    Comprehensive security health check — single command to assess posture.
    Runs checks and produces a score.
    """
    from quarr.tools.blue_team import (
        active_connections,
        process_monitor,
    )
    from quarr.tools.vuln_assess import hardening_check, patch_assessment

    results = []
    threats = 0  # active threats (suspicious conns/processes)

    # 1. Hardening
    results.append("═══ SECURITY HEALTH CHECK ═══\n")
    harden = hardening_check()
    results.append(harden)

    # Parse the hardening pass percentage as the baseline posture score. Fall
    # back to counting failures if the expected "(NN%)" marker is absent.
    import re as _re
    m = _re.search(r"\((\d+)%\)", harden)
    if m:
        hardening_pct = int(m.group(1))
    else:
        fails = harden.count("❌")
        hardening_pct = max(0, 100 - fails * 10)

    # 2. Patches
    results.append("\n\n═══ PATCH STATUS ═══")
    patches = patch_assessment()
    results.append(patches)

    # 3. Suspicious connections
    results.append("\n\n═══ NETWORK ═══")
    conns = active_connections("suspicious")
    if "No suspicious" not in conns:
        threats += 1
        results.append("⚠️ Suspicious connections detected")
    else:
        results.append("✅ No suspicious connections")

    # 4. Process check
    procs = process_monitor()
    if "SUSPICIOUS PROCESSES" in procs:
        threats += 1
        results.append("⚠️ Suspicious processes detected")
    else:
        results.append("✅ No suspicious processes")

    # Score: start from the real hardening percentage (not an arbitrary penalty
    # that saturates to 0), then subtract for each ACTIVE threat found. This
    # keeps the overall score aligned with the hardening report instead of
    # diverging from it.
    score = max(0, min(100, hardening_pct - threats * 20))

    results.append(f"\n\n═══ OVERALL SCORE: {score}/100 ═══")
    results.append(f"(hardening baseline {hardening_pct}%, {threats} active threat(s))")
    if score >= 80:
        results.append("🟢 HEALTHY")
    elif score >= 50:
        results.append("🟡 NEEDS ATTENTION")
    else:
        results.append("🔴 AT RISK")

    results.append(f"Timestamp: {datetime.now().isoformat()}")

    return "\n".join(results)


# ============================================================
# Security Playbooks
# ============================================================

PLAYBOOKS = {
    "brute_force_response": {
        "name": "Brute Force Response",
        "description": "Respond to detected brute-force attack",
        "steps": [
            {"action": "log_analysis", "args": {"log_type": "auth", "filter_pattern": "Failed"}, "description": "Analyze failed login attempts"},
            {"action": "active_connections", "args": {"filter_type": "established"}, "description": "Check current connections"},
            {"action": "user_audit", "args": {}, "description": "Audit user sessions"},
        ],
        "auto_actions": ["Block source IP if > 10 failures", "Enable fail2ban if not active"],
    },
    "malware_response": {
        "name": "Malware Incident Response",
        "description": "Respond to suspected malware infection",
        "steps": [
            {"action": "process_monitor", "args": {}, "description": "Check for suspicious processes"},
            {"action": "active_connections", "args": {"filter_type": "suspicious"}, "description": "Check C2 connections"},
            {"action": "suspicious_files", "args": {"directory": "/tmp", "days": 3}, "description": "Find suspicious files"},
            {"action": "cron_audit", "args": {}, "description": "Check persistence"},
            {"action": "file_integrity_check", "args": {"directory": "/usr/bin", "days": 7}, "description": "Check binary integrity"},
        ],
        "auto_actions": ["Isolate system", "Preserve evidence", "Block C2 IPs"],
    },
    "data_breach_response": {
        "name": "Data Breach Response",
        "description": "Respond to suspected data breach/exfiltration",
        "steps": [
            {"action": "active_connections", "args": {"filter_type": "established"}, "description": "Check outbound connections"},
            {"action": "dns_anomaly_check", "args": {}, "description": "Check DNS exfiltration"},
            {"action": "log_analysis", "args": {"log_type": "auth"}, "description": "Check access logs"},
            {"action": "user_audit", "args": {}, "description": "Audit user access"},
            {"action": "log_timeline", "args": {"hours": 48}, "description": "Build incident timeline"},
        ],
        "auto_actions": ["Identify affected data", "Notify stakeholders", "Preserve logs"],
    },
    "web_attack_response": {
        "name": "Web Application Attack Response",
        "description": "Respond to web application attack (SQLi, XSS, etc)",
        "steps": [
            {"action": "log_analysis", "args": {"log_type": "apache", "filter_pattern": "select|union|script|alert"}, "description": "Check web logs for attack patterns"},
            {"action": "active_connections", "args": {"filter_type": "established"}, "description": "Check attacker connections"},
            {"action": "file_integrity_check", "args": {"directory": "/var/www", "days": 3}, "description": "Check webroot for changes"},
        ],
        "auto_actions": ["Block attacker IP", "Check for webshells", "Review WAF rules"],
    },
}


def list_playbooks() -> str:
    """List available security playbooks."""
    lines = ["=== SECURITY PLAYBOOKS ===\n"]
    for key, pb in PLAYBOOKS.items():
        lines.append(f"📋 {key}")
        lines.append(f"   {pb['name']}: {pb['description']}")
        lines.append(f"   Steps: {len(pb['steps'])}")
    return "\n".join(lines)


def get_playbook(name: str) -> str:
    """Get playbook details."""
    pb = PLAYBOOKS.get(name)
    if not pb:
        return f"[ERROR] Unknown playbook. Available: {', '.join(PLAYBOOKS.keys())}"

    lines = [
        f"=== PLAYBOOK: {pb['name']} ===",
        f"Description: {pb['description']}",
        "\nSteps:",
    ]
    for i, step in enumerate(pb["steps"], 1):
        lines.append(f"  {i}. {step['action']}({step['args']}) — {step['description']}")

    lines.append("\nRecommended Actions:")
    for action in pb.get("auto_actions", []):
        lines.append(f"  → {action}")

    return "\n".join(lines)


# ============================================================
# Security Metrics
# ============================================================

def security_metrics() -> str:
    """Generate security metrics dashboard (text-based)."""
    from quarr.tools.blue_team import active_connections, log_analysis

    metrics = {}

    # Failed logins (24h)
    failed = log_analysis("auth", lines=500, filter_pattern="Failed")
    metrics["failed_logins_24h"] = failed.count("Failed")

    # Active connections. `ss ... state established` filters BY state, so the
    # State column ("ESTAB") is not printed in the rows — counting "ESTAB"
    # matched nothing and the metric was always 0. Count the actual data rows
    # instead (skip the header and any tool error/empty markers).
    conns_raw = active_connections("established")
    conn_lines = [
        ln for ln in conns_raw.split("\n")
        if ln.strip()
        and not ln.startswith(("[", "Netid", "State", "Recv-Q"))
    ]
    metrics["active_connections"] = len(conn_lines)

    # Listening ports
    from quarr.tools.blue_team import port_audit
    ports = port_audit()
    metrics["listening_ports"] = ports.count("LISTEN")

    lines = [
        "═══ SECURITY METRICS ═══",
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        f"  Failed logins (24h):    {metrics['failed_logins_24h']}",
        f"  Active connections:     {metrics['active_connections']}",
        f"  Listening ports:        {metrics['listening_ports']}",
        "",
    ]

    # Thresholds
    if metrics["failed_logins_24h"] > 100:
        lines.append("  🚨 HIGH failed login rate — possible brute-force")
    if metrics["active_connections"] > 50:
        lines.append("  ⚠️ High connection count — review established connections")

    return "\n".join(lines)


# ============================================================
# Compliance Report
# ============================================================

def compliance_report(framework: str = "cis") -> str:
    """
    Generate compliance status report.
    framework: cis (CIS Benchmark), pci (PCI-DSS basic), hipaa (HIPAA basic)
    """
    from quarr.tools.vuln_assess import hardening_check, linux_security_audit

    if framework == "cis":
        audit = linux_security_audit()
        harden = hardening_check()

        return (
            f"═══ CIS BENCHMARK COMPLIANCE REPORT ═══\n"
            f"Date: {datetime.now().strftime('%Y-%m-%d')}\n\n"
            f"{harden}\n\n"
            f"{'─' * 50}\n\n"
            f"DETAILED AUDIT:\n{audit}"
        )

    elif framework == "pci":
        checks = []          # (name, passed) — automatically verified controls
        manual = []          # controls that require manual review (not scored)
        # PCI-DSS basic checks
        from quarr.tools.blue_team import firewall_status
        fw = firewall_status()
        checks.append(("Req 1: Firewall", _is_active(fw)))

        from quarr.tools.vuln_assess import config_audit
        ssh = config_audit("ssh")
        checks.append(("Req 2: No defaults", "PermitRootLogin no" in ssh or "permitrootlogin no" in ssh.lower()))
        checks.append(("Req 10: Logging", os.path.exists("/var/log/auth.log")))

        # Controls that cannot be verified automatically must NOT be reported as
        # passing — that would misrepresent compliance in a professional report.
        manual.extend([
            "Req 4: Encrypt transmission of cardholder data",
            "Req 6: Develop/maintain secure systems",
            "Req 8: Unique IDs & authentication",
        ])

        lines = [f"═══ PCI-DSS BASIC COMPLIANCE ═══\nDate: {datetime.now().strftime('%Y-%m-%d')}\n"]
        passed = 0
        for name, ok in checks:
            icon = "✅" if ok else "❌"
            lines.append(f"  {icon} {name}")
            if ok:
                passed += 1
        for name in manual:
            lines.append(f"  ⚠️  {name} — MANUAL REVIEW REQUIRED (not scored)")
        lines.append(f"\nScore (automated checks only): {passed}/{len(checks)}")
        lines.append(f"Manual review required: {len(manual)} control(s)")
        lines.append("\nNOTE: Automated checks are a partial subset of PCI-DSS. "
                     "A full assessment requires manual review of the flagged controls.")
        return "\n".join(lines)

    elif framework == "hipaa":
        # HIPAA Security Rule — basic technical safeguards that can be checked.
        checks = []
        manual = []
        checks.append(("§164.312(b): Audit logging", os.path.exists("/var/log/auth.log")))

        from quarr.tools.vuln_assess import config_audit
        ssh = config_audit("ssh")
        checks.append(("§164.312(e): Transmission security (SSH hardening)",
                       "PermitRootLogin no" in ssh or "permitrootlogin no" in ssh.lower()))

        from quarr.tools.blue_team import firewall_status
        fw = firewall_status()
        checks.append(("§164.312(a): Access control (firewall)",
                       _is_active(fw)))

        manual.extend([
            "§164.312(a)(2)(iv): Encryption of ePHI at rest",
            "§164.308: Administrative safeguards (policies, training)",
            "§164.310: Physical safeguards (facility access)",
        ])

        lines = [f"═══ HIPAA SECURITY RULE (BASIC) ═══\nDate: {datetime.now().strftime('%Y-%m-%d')}\n"]
        passed = 0
        for name, ok in checks:
            lines.append(f"  {'✅' if ok else '❌'} {name}")
            if ok:
                passed += 1
        for name in manual:
            lines.append(f"  ⚠️  {name} — MANUAL REVIEW REQUIRED (not scored)")
        lines.append(f"\nScore (automated checks only): {passed}/{len(checks)}")
        lines.append(f"Manual review required: {len(manual)} safeguard(s)")
        lines.append("\nNOTE: Technical safeguards only. Administrative and physical "
                     "safeguards require manual assessment.")
        return "\n".join(lines)

    return f"[ERROR] Unknown framework: {framework}. Available: cis, pci, hipaa"
