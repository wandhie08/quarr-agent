"""
vuln_assess_tools.py - M24: Vulnerability Assessment

Extended vulnerability assessment:
- CIS Benchmark compliance check
- Security configuration audit
- Patch assessment
- Hardening check
"""

import os
import re
import shlex
import subprocess


def _shell(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = result.stdout
        if result.stderr:
            out += f"\n[STDERR] {result.stderr}"
        return out if out.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def _run(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        out = result.stdout
        if result.stderr:
            out += f"\n[STDERR] {result.stderr}"
        return out if out.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd.split()[0]}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


# ============================================================
# Linux Security Audit
# ============================================================

def linux_security_audit() -> str:
    """
    Comprehensive Linux security audit based on CIS Benchmark:
    - Password policy
    - SSH configuration
    - Filesystem permissions
    - Network configuration
    - Kernel parameters
    - Authentication settings
    """
    findings = []
    info = []

    # 1. Password policy
    info.append("=== 1. PASSWORD POLICY ===")
    pass_max = _shell("grep PASS_MAX_DAYS /etc/login.defs 2>/dev/null | grep -v '^#'", timeout=3)
    pass_min = _shell("grep PASS_MIN_DAYS /etc/login.defs 2>/dev/null | grep -v '^#'", timeout=3)
    pass_len = _shell("grep PASS_MIN_LEN /etc/login.defs 2>/dev/null | grep -v '^#'", timeout=3)
    info.append(f"  {pass_max.strip()}")
    info.append(f"  {pass_min.strip()}")
    info.append(f"  {pass_len.strip()}")

    if "99999" in pass_max:
        findings.append("[MEDIUM] Password expiry not enforced (PASS_MAX_DAYS=99999)")

    # 2. SSH configuration
    info.append("\n=== 2. SSH CONFIGURATION ===")
    ssh_checks = {
        "PermitRootLogin": ("no", "[HIGH] SSH root login permitted"),
        "PasswordAuthentication": ("no", "[MEDIUM] SSH password auth enabled (should use keys)"),
        "PermitEmptyPasswords": ("no", "[HIGH] SSH allows empty passwords"),
        "X11Forwarding": ("no", "[LOW] SSH X11 forwarding enabled"),
        "MaxAuthTries": (None, None),
        "Protocol": (None, None),
    }
    ssh_config = _shell("cat /etc/ssh/sshd_config 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
    for key, (expected, msg) in ssh_checks.items():
        match = re.search(rf'^{key}\s+(\S+)', ssh_config, re.MULTILINE | re.IGNORECASE)
        if match:
            value = match.group(1)
            info.append(f"  {key}: {value}")
            if expected and value.lower() != expected:
                findings.append(msg)
        elif expected:
            info.append(f"  {key}: (not set, default)")

    # 3. SUID/SGID binaries
    info.append("\n=== 3. SUID/SGID BINARIES ===")
    suid = _shell("find /usr -perm -4000 -type f 2>/dev/null | wc -l", timeout=10)
    info.append(f"  SUID binaries: {suid.strip()}")
    # Check for unusual SUID
    unusual = _shell("find /usr -perm -4000 -type f 2>/dev/null | grep -vE '(sudo|su|passwd|ping|mount|umount|chsh|gpasswd|newgrp|chfn|pkexec)' | head -5", timeout=10)
    if unusual.strip() and "[No output]" not in unusual:
        findings.append(f"[MEDIUM] Unusual SUID binaries: {unusual.strip()}")

    # 4. World-writable files
    info.append("\n=== 4. PERMISSIONS ===")
    world_writable = _shell("find /etc /usr -type f -perm -o+w 2>/dev/null | head -5", timeout=10)
    if world_writable.strip() and "[No output]" not in world_writable:
        findings.append("[HIGH] World-writable files in system dirs")
        info.append(f"  World-writable: {world_writable.strip()}")

    # 5. Kernel security
    info.append("\n=== 5. KERNEL SECURITY ===")
    kernel_checks = {
        "net.ipv4.ip_forward": ("0", "[MEDIUM] IP forwarding enabled"),
        "net.ipv4.conf.all.accept_redirects": ("0", "[LOW] ICMP redirects accepted"),
        "net.ipv4.conf.all.send_redirects": ("0", "[LOW] ICMP redirects sent"),
        "net.ipv4.conf.all.accept_source_route": ("0", "[MEDIUM] Source routing accepted"),
        "kernel.randomize_va_space": ("2", "[HIGH] ASLR not fully enabled"),
        "fs.suid_dumpable": ("0", "[MEDIUM] SUID core dumps enabled"),
    }
    for param, (expected, msg) in kernel_checks.items():
        value = _shell(f"sysctl -n {param} 2>/dev/null", timeout=3).strip()
        info.append(f"  {param} = {value}")
        if value and value != expected:
            findings.append(msg)

    # 6. Unattended upgrades
    info.append("\n=== 6. PATCHING ===")
    auto_upgrade = _shell("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'", timeout=3)
    if not auto_upgrade.strip() or "ii" not in auto_upgrade:
        findings.append("[MEDIUM] Unattended-upgrades not installed")
        info.append("  unattended-upgrades: NOT installed")
    else:
        info.append("  unattended-upgrades: installed")

    # 7. Open ports
    info.append("\n=== 7. LISTENING SERVICES ===")
    ports = _shell("ss -tulpn | grep LISTEN | wc -l", timeout=3)
    info.append(f"  Listening ports: {ports.strip()}")

    # Summary
    output = "\n".join(info)
    output += f"\n\n=== FINDINGS ({len(findings)}) ===\n"
    if findings:
        output += "\n".join(findings)
        high = sum(1 for f in findings if "[HIGH]" in f)
        med = sum(1 for f in findings if "[MEDIUM]" in f)
        output += f"\n\nRisk: {high} HIGH, {med} MEDIUM, {len(findings)-high-med} LOW"
    else:
        output += "✅ No significant findings"

    return output


def patch_assessment() -> str:
    """Check for available security updates."""
    results = []

    # Debian/Ubuntu
    apt = _shell("apt list --upgradable 2>/dev/null | head -30", timeout=30)
    if apt.strip() and "Listing" in apt:
        results.append(f"=== APT UPGRADABLE ===\n{apt}")
        security = _shell("apt list --upgradable 2>/dev/null | grep -i security | wc -l", timeout=10)
        results.append(f"Security updates: {security.strip()}")

    # Kernel version
    kernel = _shell("uname -r", timeout=3)
    results.append(f"\n=== KERNEL ===\nRunning: {kernel.strip()}")
    available = _shell("dpkg -l linux-image-* 2>/dev/null | grep '^ii' | tail -3", timeout=5)
    results.append(f"Installed kernels:\n{available}")

    # Last update
    last_update = _shell("stat -c %y /var/lib/apt/lists/ 2>/dev/null | cut -d' ' -f1", timeout=3)
    results.append(f"\nLast apt update: {last_update.strip()}")

    return "\n".join(results) if results else "[INFO] Cannot determine package status"


def config_audit(service: str = "all") -> str:
    """
    Security configuration audit for services.
    service: all, ssh, apache, nginx, mysql, php
    """
    results = []

    if service in ("all", "ssh"):
        results.append("=== SSH CONFIG AUDIT ===")
        ssh = _shell("sshd -T 2>/dev/null | grep -iE 'permitroot|password|empty|maxauth|x11|pubkey|allow|deny' | sort", timeout=5)
        results.append(ssh if ssh.strip() else "  sshd not accessible")

    if service in ("all", "apache"):
        results.append("\n=== APACHE CONFIG AUDIT ===")
        apache_conf = "/etc/apache2/apache2.conf"
        if os.path.exists(apache_conf):
            checks = _shell(f"grep -iE 'ServerTokens|ServerSignature|TraceEnable|Options' {apache_conf} | grep -v '^#'", timeout=5)
            results.append(checks if checks.strip() else "  Default config")
            if "Prod" not in (checks or ""):
                results.append("  ⚠️ ServerTokens not set to Prod (information disclosure)")
        else:
            results.append("  Apache not installed")

    if service in ("all", "nginx"):
        results.append("\n=== NGINX CONFIG AUDIT ===")
        nginx_conf = "/etc/nginx/nginx.conf"
        if os.path.exists(nginx_conf):
            checks = _shell(f"grep -iE 'server_tokens|ssl_protocols|ssl_ciphers|add_header' {nginx_conf} | grep -v '^#' | head -10", timeout=5)
            results.append(checks if checks.strip() else "  Default config")
        else:
            results.append("  Nginx not installed")

    if service in ("all", "mysql"):
        results.append("\n=== MYSQL CONFIG AUDIT ===")
        mysql_conf = _shell("find /etc/mysql -name '*.cnf' -exec grep -l 'bind-address\\|skip-networking' {} \\; 2>/dev/null", timeout=5)
        if mysql_conf.strip():
            conf_path = shlex.quote(mysql_conf.strip().split()[0])
            bind = _shell(f"grep 'bind-address' {conf_path} 2>/dev/null | grep -v '^#'", timeout=3)
            results.append(f"  bind-address: {bind.strip() or 'not set (⚠️ listening on all interfaces)'}")
        else:
            results.append("  MySQL not installed or no config found")

    return "\n".join(results)


def hardening_check() -> str:
    """Quick hardening checklist — what's done vs what's missing."""
    checks = []

    # Firewall
    ufw = _shell("ufw status 2>/dev/null", timeout=3)
    checks.append(("Firewall enabled", "active" in ufw.lower() and "inactive" not in ufw.lower()))

    # SSH root login
    ssh_root = _shell("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null", timeout=3)
    checks.append(("SSH root login disabled", "no" in ssh_root.lower()))

    # Password auth
    ssh_pass = _shell("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null", timeout=3)
    checks.append(("SSH password auth disabled", "no" in ssh_pass.lower()))

    # Automatic updates
    auto = _shell("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'", timeout=3)
    checks.append(("Automatic security updates", bool(auto.strip())))

    # ASLR
    aslr = _shell("sysctl kernel.randomize_va_space 2>/dev/null", timeout=3)
    checks.append(("ASLR enabled", "= 2" in aslr))

    # Core dumps disabled
    core = _shell("sysctl fs.suid_dumpable 2>/dev/null", timeout=3)
    checks.append(("SUID core dumps disabled", "= 0" in core))

    # IP forwarding disabled
    fwd = _shell("sysctl net.ipv4.ip_forward 2>/dev/null", timeout=3)
    checks.append(("IP forwarding disabled", "= 0" in fwd))

    # No empty passwords
    empty = _shell("grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null", timeout=3)
    checks.append(("SSH empty passwords blocked", "no" in empty.lower() or not empty.strip()))

    # Fail2ban
    f2b = _shell("systemctl is-active fail2ban 2>/dev/null", timeout=3)
    checks.append(("Fail2ban active", "active" in f2b.lower() and "inactive" not in f2b.lower()))

    # Build output
    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    score = (passed / total * 100) if total > 0 else 0

    lines = [
        "=== HARDENING CHECKLIST ===",
        f"Score: {passed}/{total} ({score:.0f}%)\n",
    ]
    for name, ok in checks:
        icon = "✅" if ok else "❌"
        lines.append(f"  {icon} {name}")

    if score >= 80:
        lines.append("\n🟢 Good hardening posture")
    elif score >= 50:
        lines.append("\n🟡 Moderate — needs improvement")
    else:
        lines.append("\n🔴 Poor — significant hardening needed")

    return "\n".join(lines)
