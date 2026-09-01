"""
threat_hunting_tools.py - M20: Threat Hunting & Detection

Proaktif mencari indikator kompromi (IOC), rootkit, anomaly.
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
# IOC Search
# ============================================================

def ioc_search(ioc_type: str, value: str) -> str:
    """
    Cari Indicator of Compromise di sistem.
    ioc_type: ip, domain, hash, filename, string
    """
    value = value.strip()
    if not value:
        return "[ERROR] IOC value cannot be empty"

    results = []

    if ioc_type == "ip":
        # Search in logs and connections
        results.append("=== CONNECTIONS ===")
        results.append(_shell(f"ss -tunapl | grep {shlex.quote(value)}", timeout=5))
        results.append("\n=== AUTH LOG ===")
        results.append(_shell(f"grep {shlex.quote(value)} /var/log/auth.log 2>/dev/null | tail -20", timeout=5))
        results.append("\n=== SYSLOG ===")
        results.append(_shell(f"grep {shlex.quote(value)} /var/log/syslog 2>/dev/null | tail -20", timeout=5))

    elif ioc_type == "domain":
        results.append("=== DNS CACHE ===")
        results.append(_shell(f"grep -r {shlex.quote(value)} /var/log/ 2>/dev/null | tail -20", timeout=10))
        results.append("\n=== HOSTS FILE ===")
        results.append(_shell(f"grep {shlex.quote(value)} /etc/hosts 2>/dev/null", timeout=3))

    elif ioc_type == "hash":
        # Search for file with matching hash
        results.append(f"=== SEARCHING FILES WITH HASH: {value[:16]}... ===")
        if len(value) == 32:  # MD5
            alg = "md5sum"
        elif len(value) == 64:  # SHA256
            alg = "sha256sum"
        else:
            alg = "sha1sum"
        results.append(_shell(
            f"find /tmp /var/tmp /dev/shm /home -type f -exec {alg} {{}} \\; 2>/dev/null | grep {shlex.quote(value)} | head -10",
            timeout=30
        ))

    elif ioc_type == "filename":
        results.append(f"=== SEARCHING: {value} ===")
        results.append(_shell(f"find / -name {shlex.quote(value)} -type f 2>/dev/null | head -20", timeout=15))

    elif ioc_type == "string":
        results.append(f"=== SEARCHING STRING IN /tmp, /var/tmp, /dev/shm ===")
        results.append(_shell(
            f"grep -rl {shlex.quote(value)} /tmp/ /var/tmp/ /dev/shm/ 2>/dev/null | head -20",
            timeout=10
        ))

    return "\n".join(results)


def suspicious_files(directory: str = "/tmp", days: int = 3) -> str:
    """Cari file mencurigakan: baru dibuat, hidden, executable di /tmp, dll."""
    directory = directory.strip()
    if ".." in directory:
        return "[ERROR] Invalid directory"
    days = min(days, 30)

    results = []

    # Recently created files
    results.append(f"=== NEW FILES (last {days} days) in {directory} ===")
    results.append(_shell(f"find {shlex.quote(directory)} -type f -ctime -{days} -ls 2>/dev/null | head -30", timeout=10))

    # Hidden files
    results.append(f"\n=== HIDDEN FILES in {directory} ===")
    results.append(_shell(f"find {shlex.quote(directory)} -name '.*' -type f -ls 2>/dev/null | head -20", timeout=10))

    # Executable files in temp directories
    results.append(f"\n=== EXECUTABLES in {directory} ===")
    results.append(_shell(f"find {shlex.quote(directory)} -type f -executable -ls 2>/dev/null | head -20", timeout=10))

    # World-writable
    results.append(f"\n=== WORLD-WRITABLE FILES ===")
    results.append(_shell(f"find {shlex.quote(directory)} -type f -perm -o+w -ls 2>/dev/null | head -20", timeout=10))

    return "\n".join(results)


# ============================================================
# Rootkit & Malware Detection
# ============================================================

def rootkit_scan() -> str:
    """Scan untuk rootkit menggunakan chkrootkit dan rkhunter."""
    results = []

    chk = _run("chkrootkit -q", timeout=60)
    if "[ERROR]" not in chk:
        results.append(f"=== CHKROOTKIT ===\n{chk}")

    rk = _run("rkhunter --check --skip-keypress --report-warnings-only", timeout=120)
    if "[ERROR]" not in rk:
        results.append(f"\n=== RKHUNTER ===\n{rk}")

    if not results:
        return "[INFO] Neither chkrootkit nor rkhunter found. Install: apt install chkrootkit rkhunter"
    return "\n".join(results)


def yara_scan(directory: str, rules_path: str = "") -> str:
    """Scan files dengan YARA rules untuk malware detection."""
    directory = directory.strip()
    if ".." in directory:
        return "[ERROR] Invalid directory"

    if not rules_path:
        # Check for common YARA rule locations
        common_paths = [
            "/usr/share/yara-rules/",
            "/opt/yara-rules/",
            "/etc/yara/",
        ]
        for p in common_paths:
            if os.path.exists(p):
                rules_path = p
                break

    if not rules_path or not os.path.exists(rules_path):
        return "[ERROR] No YARA rules found. Provide rules_path or install: apt install yara yara-rules"

    cmd = f"yara -r {shlex.quote(rules_path)} {shlex.quote(directory)}"
    return _run(cmd, timeout=60)


# ============================================================
# Network Anomaly Detection
# ============================================================

def network_capture(interface: str = "eth0", count: int = 100, filter_expr: str = "") -> str:
    """Capture network packets untuk analisis."""
    count = min(count, 500)
    cmd = f"timeout 10 tcpdump -i {shlex.quote(interface)} -c {count} -nn"
    if filter_expr:
        cmd += f" {shlex.quote(filter_expr)}"
    cmd += " 2>&1 | tail -50"
    return _shell(cmd, timeout=15)


def dns_anomaly_check(interface: str = "eth0") -> str:
    """Deteksi DNS anomaly: tunneling, DGA domains, unusual queries."""
    # Capture DNS traffic
    cmd = f"timeout 10 tcpdump -i {shlex.quote(interface)} -nn port 53 -c 50 2>&1"
    out = _shell(cmd, timeout=15)

    results = [f"=== DNS TRAFFIC (last 10s) ===\n{out}"]

    # Check for anomalies
    anomalies = []
    for line in out.split("\n"):
        # Long domain names (possible tunneling)
        domain_match = re.search(r'A\? (\S+)', line)
        if domain_match:
            domain = domain_match.group(1)
            if len(domain) > 50:
                anomalies.append(f"⚠️ Long domain (possible tunneling): {domain[:80]}")
        # TXT record queries (possible C2/exfil)
        if " TXT?" in line:
            anomalies.append(f"⚠️ TXT query: {line.strip()}")

    if anomalies:
        results.append("\n=== ANOMALIES ===\n" + "\n".join(anomalies[:10]))

    return "\n".join(results)


# ============================================================
# Baseline & Hash Verification
# ============================================================

def hash_verify(filepath: str) -> str:
    """Calculate SHA256 hash of file for integrity check."""
    filepath = filepath.strip()
    if ".." in filepath:
        return "[ERROR] Invalid path"
    return _run(f"sha256sum {shlex.quote(filepath)}", timeout=10)


def baseline_compare(directory: str = "/usr/bin", baseline_file: str = "") -> str:
    """
    Compare current state vs baseline.
    If no baseline exists, create one.
    """
    directory = directory.strip()
    if ".." in directory:
        return "[ERROR] Invalid directory"

    baseline_dir = "engagements/baselines"
    os.makedirs(baseline_dir, exist_ok=True)
    safe_name = directory.replace("/", "_").strip("_")
    default_baseline = os.path.join(baseline_dir, f"{safe_name}.baseline")
    baseline_file = baseline_file or default_baseline

    if not os.path.exists(baseline_file):
        # Create baseline
        cmd = f"find {shlex.quote(directory)} -type f -exec sha256sum {{}} \\; 2>/dev/null"
        out = _shell(cmd, timeout=30)
        with open(baseline_file, "w") as f:
            f.write(out)
        return f"✅ Baseline created: {baseline_file} ({len(out.splitlines())} files)"

    # Compare
    current_cmd = f"find {shlex.quote(directory)} -type f -exec sha256sum {{}} \\; 2>/dev/null"
    current = _shell(current_cmd, timeout=30)

    with open(baseline_file) as f:
        baseline = f.read()

    baseline_set = set(baseline.strip().splitlines())
    current_set = set(current.strip().splitlines())

    added = current_set - baseline_set
    removed = baseline_set - current_set

    results = [f"=== BASELINE COMPARISON ({directory}) ==="]
    if not added and not removed:
        results.append("✅ No changes detected")
    else:
        if added:
            results.append(f"\n⚠️ CHANGED/NEW ({len(added)}):")
            for line in list(added)[:20]:
                results.append(f"  + {line}")
        if removed:
            results.append(f"\n⚠️ REMOVED ({len(removed)}):")
            for line in list(removed)[:20]:
                results.append(f"  - {line}")

    return "\n".join(results)
