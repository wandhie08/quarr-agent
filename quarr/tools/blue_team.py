"""
blue_team_tools.py - M19: Blue Team Defense & Monitoring

Tools untuk deteksi serangan, hardening, dan incident response awal.
"""

import subprocess
import shlex
import re
import os
from typing import Dict, Any


def _run(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            shlex.split(cmd), capture_output=True, text=True, timeout=timeout
        )
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


def _shell(cmd: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout
        if result.stderr:
            out += f"\n[STDERR] {result.stderr}"
        return out if out.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {timeout}s"
    except Exception as e:
        return f"[ERROR] {str(e)}"


# ============================================================
# Firewall
# ============================================================

def firewall_status() -> str:
    """Cek status firewall rules (iptables + ufw)."""
    results = []
    ufw = _run("ufw status verbose", timeout=5)
    if "[ERROR]" not in ufw:
        results.append(f"=== UFW ===\n{ufw}")
    ipt = _run("sudo iptables -L -n -v --line-numbers", timeout=5)
    if "[ERROR]" not in ipt:
        results.append(f"=== IPTABLES ===\n{ipt}")
    return "\n".join(results) if results else "[INFO] No firewall detected"


def firewall_block(ip_address: str) -> str:
    """Block IP address di firewall."""
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip_address.strip()):
        return f"[ERROR] Invalid IP: {ip_address}"
    cmd = f"sudo iptables -A INPUT -s {shlex.quote(ip_address.strip())} -j DROP"
    out = _run(cmd, timeout=5)
    if "[ERROR]" not in out:
        return f"✅ Blocked: {ip_address}"
    return out


def firewall_unblock(ip_address: str) -> str:
    """Unblock IP address dari firewall."""
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$', ip_address.strip()):
        return f"[ERROR] Invalid IP: {ip_address}"
    cmd = f"sudo iptables -D INPUT -s {shlex.quote(ip_address.strip())} -j DROP"
    out = _run(cmd, timeout=5)
    if "[ERROR]" not in out:
        return f"✅ Unblocked: {ip_address}"
    return out


# ============================================================
# Log Analysis
# ============================================================

def log_analysis(log_type: str = "auth", lines: int = 100, filter_pattern: str = "") -> str:
    """Analisis system logs. log_type: auth, syslog, kern, ufw, fail2ban, apache, nginx."""
    log_map = {
        "auth": "/var/log/auth.log",
        "syslog": "/var/log/syslog",
        "kern": "/var/log/kern.log",
        "ufw": "/var/log/ufw.log",
        "fail2ban": "/var/log/fail2ban.log",
        "apache": "/var/log/apache2/access.log",
        "nginx": "/var/log/nginx/access.log",
    }
    log_path = log_map.get(log_type)
    if not log_path:
        return f"[ERROR] Unknown log type. Available: {', '.join(log_map.keys())}"

    lines = min(lines, 500)
    cmd = f"tail -n {lines} {log_path}"
    if filter_pattern:
        cmd += f" | grep -i {shlex.quote(filter_pattern)}"
    return _shell(cmd, timeout=10)


# ============================================================
# Network Monitoring
# ============================================================

def active_connections(filter_type: str = "all") -> str:
    """Cek koneksi jaringan aktif. filter: all, established, listening, suspicious."""
    if filter_type == "established":
        cmd = "ss -tunapl state established"
    elif filter_type == "listening":
        cmd = "ss -tulpn"
    elif filter_type == "suspicious":
        # Cari koneksi ke port yang tidak biasa atau reverse shell indicators
        cmd = "ss -tunapl | grep -E '(:4444|:5555|:1234|:9001|:8888|:31337|ESTAB.*[0-9]+\\.[0-9]+)' || echo 'No suspicious connections found'"
    else:
        cmd = "ss -tunapl"
    return _shell(cmd, timeout=10)


def port_audit() -> str:
    """Audit semua listening ports — cari backdoor/unauthorized services."""
    out = _shell("ss -tulpn | sort -t: -k2 -n", timeout=10)
    # Highlight suspicious ports
    suspicious = []
    for line in out.split("\n"):
        if any(p in line for p in [":4444", ":5555", ":1234", ":9001", ":31337", ":6666", ":6667"]):
            suspicious.append(f"⚠️ SUSPICIOUS: {line.strip()}")
    result = out
    if suspicious:
        result += "\n\n=== SUSPICIOUS PORTS ===\n" + "\n".join(suspicious)
    return result


# ============================================================
# Process & System Monitoring
# ============================================================

def process_monitor(filter_pattern: str = "") -> str:
    """Cek proses berjalan — deteksi reverse shell, miner, suspicious processes."""
    if filter_pattern:
        cmd = f"ps auxf | grep -i {shlex.quote(filter_pattern)} | grep -v grep"
    else:
        cmd = "ps auxf --sort=-%cpu | head -50"
    out = _shell(cmd, timeout=10)

    # Scan for suspicious processes
    suspicious_patterns = [
        r'/bin/sh -i', r'/bin/bash -i', r'nc -e', r'ncat.*-e',
        r'python.*-c.*import socket', r'perl.*socket', r'ruby.*socket',
        r'xmrig', r'minerd', r'cpuminer', r'cryptonight',
        r'/tmp/\.\w+', r'/dev/shm/\.\w+',
    ]
    suspicious = []
    for line in out.split("\n"):
        for pat in suspicious_patterns:
            if re.search(pat, line, re.IGNORECASE):
                suspicious.append(f"🚨 {line.strip()}")
                break

    if suspicious:
        out += "\n\n=== SUSPICIOUS PROCESSES ===\n" + "\n".join(suspicious)
    return out


def service_audit() -> str:
    """Audit systemd services — running + enabled at boot."""
    running = _shell("systemctl list-units --type=service --state=running --no-pager --no-legend | head -50", timeout=10)
    enabled = _shell("systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | head -50", timeout=10)
    return f"=== RUNNING SERVICES ===\n{running}\n\n=== ENABLED AT BOOT ===\n{enabled}"


# ============================================================
# User & Access Audit
# ============================================================

def user_audit() -> str:
    """Audit users: login history, active sessions, suspicious accounts."""
    results = []

    # Active sessions
    who = _run("who", timeout=5)
    results.append(f"=== ACTIVE SESSIONS ===\n{who}")

    # Last logins
    last = _shell("last -n 20 -a", timeout=5)
    results.append(f"\n=== LAST LOGINS ===\n{last}")

    # Failed logins
    failed = _shell("lastb -n 20 2>/dev/null || grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20", timeout=5)
    results.append(f"\n=== FAILED LOGINS ===\n{failed}")

    # Users with shells
    shells = _shell("grep -E '/bin/(bash|sh|zsh|fish)$' /etc/passwd", timeout=5)
    results.append(f"\n=== USERS WITH SHELL ===\n{shells}")

    # Sudoers
    sudoers = _shell("grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' | head -20; getent group sudo 2>/dev/null", timeout=5)
    results.append(f"\n=== SUDO ACCESS ===\n{sudoers}")

    return "\n".join(results)


def cron_audit() -> str:
    """Audit cron jobs — cari persistence mechanism."""
    results = []

    # System cron
    sys_cron = _shell("ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ 2>/dev/null", timeout=5)
    results.append(f"=== SYSTEM CRON ===\n{sys_cron}")

    # User crontabs
    user_cron = _shell("for u in $(cut -d: -f1 /etc/passwd); do echo \"--- $u ---\"; crontab -l -u $u 2>/dev/null; done", timeout=10)
    results.append(f"\n=== USER CRONTABS ===\n{user_cron}")

    # /etc/crontab
    crontab = _shell("cat /etc/crontab 2>/dev/null", timeout=5)
    results.append(f"\n=== /etc/crontab ===\n{crontab}")

    return "\n".join(results)


# ============================================================
# File Integrity
# ============================================================

def file_integrity_check(directory: str = "/usr/bin", days: int = 7) -> str:
    """Cek file yang dimodifikasi dalam X hari terakhir."""
    directory = directory.strip()
    if ".." in directory:
        return "[ERROR] Invalid directory"
    days = min(days, 90)
    cmd = f"find {shlex.quote(directory)} -type f -mtime -{days} -ls 2>/dev/null | head -50"
    out = _shell(cmd, timeout=15)
    # SUID/SGID files
    suid = _shell(f"find {shlex.quote(directory)} -perm -4000 -o -perm -2000 2>/dev/null | head -20", timeout=10)
    result = f"=== MODIFIED IN LAST {days} DAYS ({directory}) ===\n{out}"
    if suid.strip() and "[No output]" not in suid:
        result += f"\n\n=== SUID/SGID FILES ===\n{suid}"
    return result
