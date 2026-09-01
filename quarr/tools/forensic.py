"""
forensic_tools.py - M21: Digital Forensic

Tools untuk investigasi pasca-insiden:
- Memory analysis (Volatility)
- Disk/file forensics
- Timeline reconstruction
- Evidence preservation (chain of custody)
- Network forensics (PCAP)
"""

import subprocess
import shlex
import re
import os
from datetime import datetime
from typing import Dict, Any


def _run(cmd: str, timeout: int = 60) -> str:
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


def _shell(cmd: str, timeout: int = 60) -> str:
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


def _validate_path(p: str) -> str:
    p = p.strip()
    if not p:
        raise ValueError("Path cannot be empty")
    return p


# ============================================================
# Disk Forensics
# ============================================================

def disk_image(source: str, destination: str) -> str:
    """
    Buat forensic disk image menggunakan dcfldd/dd.
    Source: /dev/sdX atau file
    Destination: path output file (.img/.raw)
    """
    source = _validate_path(source)
    destination = _validate_path(destination)

    # Prefer dcfldd (forensic version of dd with hashing)
    dcfldd = _shell("which dcfldd", timeout=3).strip()
    if dcfldd and "[ERROR]" not in dcfldd:
        cmd = f"sudo dcfldd if={shlex.quote(source)} of={shlex.quote(destination)} hash=sha256 hashwindow=1G hashlog={destination}.hash"
    else:
        cmd = f"sudo dd if={shlex.quote(source)} of={shlex.quote(destination)} bs=4M status=progress"
    return _run(cmd, timeout=3600)


def file_recovery(image_path: str, output_dir: str = "/tmp/recovered") -> str:
    """Recover deleted files menggunakan foremost/scalpel."""
    image_path = _validate_path(image_path)
    output_dir = _validate_path(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    foremost = _shell("which foremost", timeout=3).strip()
    if foremost and "[ERROR]" not in foremost:
        cmd = f"foremost -i {shlex.quote(image_path)} -o {shlex.quote(output_dir)} -T"
    else:
        cmd = f"scalpel {shlex.quote(image_path)} -o {shlex.quote(output_dir)}"
    return _run(cmd, timeout=300)


# ============================================================
# Memory Forensics
# ============================================================

def memory_dump(output_path: str = "/tmp/memory.raw") -> str:
    """Dump live system memory."""
    output_path = _validate_path(output_path)

    # Try avml (Azure VMLinux Memory Dump - fast)
    avml = _shell("which avml", timeout=3).strip()
    if avml and "[ERROR]" not in avml:
        return _run(f"sudo avml {shlex.quote(output_path)}", timeout=120)

    # Fallback: /proc/kcore or LiME
    lime = _shell("find /lib/modules -name 'lime*.ko' 2>/dev/null | head -1", timeout=5).strip()
    if lime and "[ERROR]" not in lime:
        return _run(
            f"sudo insmod {shlex.quote(lime)} 'path={output_path} format=raw'",
            timeout=120
        )

    return "[ERROR] No memory dump tool found. Install: avml or LiME kernel module"


def memory_analysis(dump_path: str, command: str = "pslist") -> str:
    """
    Analisis memory dump dengan Volatility 3.

    Commands:
    - pslist: List running processes
    - pstree: Process tree
    - netscan: Network connections
    - cmdline: Command line arguments
    - malfind: Find injected/suspicious code
    - filescan: Scan for file objects
    - hashdump: Dump password hashes from memory
    - dlllist: List loaded DLLs
    """
    dump_path = _validate_path(dump_path)

    allowed_commands = [
        "pslist", "pstree", "netscan", "cmdline", "malfind",
        "filescan", "hashdump", "dlllist", "handles", "svcscan",
        "envars", "mutantscan",
    ]

    # Map friendly names to vol3 plugins
    plugin_map = {
        "pslist": "windows.pslist.PsList",
        "pstree": "windows.pstree.PsTree",
        "netscan": "windows.netscan.NetScan",
        "cmdline": "windows.cmdline.CmdLine",
        "malfind": "windows.malfind.Malfind",
        "filescan": "windows.filescan.FileScan",
        "hashdump": "windows.hashdump.Hashdump",
        "dlllist": "windows.dlllist.DllList",
        "handles": "windows.handles.Handles",
        "svcscan": "windows.svcscan.SvcScan",
        "envars": "windows.envars.Envars",
        "mutantscan": "windows.mutantscan.MutantScan",
    }

    if command not in allowed_commands:
        return f"[ERROR] Unknown command. Available: {', '.join(allowed_commands)}"

    plugin = plugin_map.get(command, command)

    # Try vol3
    cmd = f"vol -f {shlex.quote(dump_path)} {plugin}"
    out = _run(cmd, timeout=120)

    if "[ERROR] Command not found" in out:
        # Try python module
        cmd = f"python3 -m volatility3 -f {shlex.quote(dump_path)} {plugin}"
        out = _run(cmd, timeout=120)

    return out


# ============================================================
# File Analysis
# ============================================================

def metadata_extract(filepath: str) -> str:
    """Extract metadata dari file (EXIF, document properties, dll)."""
    filepath = _validate_path(filepath)
    return _run(f"exiftool {shlex.quote(filepath)}", timeout=10)


def string_extract(filepath: str, min_length: int = 6) -> str:
    """Extract printable strings dari binary/file."""
    filepath = _validate_path(filepath)
    min_length = min(max(min_length, 4), 20)
    out = _run(f"strings -n {min_length} {shlex.quote(filepath)}", timeout=15)
    # Limit output
    lines = out.split("\n")
    if len(lines) > 200:
        return "\n".join(lines[:200]) + f"\n\n[... {len(lines) - 200} more lines truncated]"
    return out


def binwalk_analysis(filepath: str) -> str:
    """Analisis firmware/binary untuk embedded files."""
    filepath = _validate_path(filepath)
    return _run(f"binwalk {shlex.quote(filepath)}", timeout=30)


# ============================================================
# Timeline & Log Forensics
# ============================================================

def log_timeline(hours: int = 24) -> str:
    """
    Gabungkan multiple log sources menjadi unified timeline.
    Logs: auth.log, syslog, kern.log, apache/nginx access.
    """
    hours = min(hours, 168)  # max 7 days
    results = []

    log_files = [
        ("/var/log/auth.log", "AUTH"),
        ("/var/log/syslog", "SYSTEM"),
        ("/var/log/kern.log", "KERNEL"),
        ("/var/log/apache2/access.log", "APACHE"),
        ("/var/log/nginx/access.log", "NGINX"),
    ]

    for log_path, label in log_files:
        if os.path.exists(log_path):
            # Get last N hours of logs
            cmd = f"awk -v date=\"$(date -d '{hours} hours ago' '+%b %e %H:%M')\" '$0 >= date' {log_path} 2>/dev/null | tail -30"
            out = _shell(cmd, timeout=10)
            if out.strip() and "[No output]" not in out:
                for line in out.strip().split("\n")[:30]:
                    results.append(f"[{label}] {line}")

    if not results:
        return f"[INFO] No log entries found in last {hours} hours"

    # Sort by timestamp (best effort)
    results.sort()
    return f"=== UNIFIED TIMELINE (last {hours}h) ===\n" + "\n".join(results[:100])


def browser_forensic(user: str = "") -> str:
    """Extract browser forensic data: history, downloads."""
    results = []

    if user:
        home = f"/home/{user}"
    else:
        home = os.path.expanduser("~")

    # Firefox
    firefox_dir = os.path.join(home, ".mozilla/firefox")
    if os.path.exists(firefox_dir):
        profiles = _shell(f"find {shlex.quote(firefox_dir)} -name 'places.sqlite' 2>/dev/null", timeout=5)
        if profiles.strip():
            for db in profiles.strip().split("\n")[:1]:
                db = db.strip()
                history = _shell(
                    f"sqlite3 {shlex.quote(db)} \"SELECT datetime(last_visit_date/1000000, 'unixepoch'), url FROM moz_places ORDER BY last_visit_date DESC LIMIT 30\" 2>/dev/null",
                    timeout=10
                )
                if history.strip():
                    results.append(f"=== FIREFOX HISTORY ===\n{history}")

    # Chromium/Chrome
    for browser_name in ["google-chrome", "chromium"]:
        chrome_dir = os.path.join(home, f".config/{browser_name}/Default")
        history_db = os.path.join(chrome_dir, "History")
        if os.path.exists(history_db):
            # Copy to avoid lock
            tmp_db = "/tmp/quarr_browser_history.db"
            _shell(f"cp {shlex.quote(history_db)} {tmp_db}", timeout=3)
            history = _shell(
                f"sqlite3 {tmp_db} \"SELECT datetime(last_visit_time/1000000-11644473600, 'unixepoch'), url FROM urls ORDER BY last_visit_time DESC LIMIT 30\" 2>/dev/null",
                timeout=10
            )
            if history.strip():
                results.append(f"=== {browser_name.upper()} HISTORY ===\n{history}")

    return "\n".join(results) if results else "[INFO] No browser history found"


# ============================================================
# Network Forensics
# ============================================================

def pcap_analysis(pcap_file: str, filter_expr: str = "") -> str:
    """Analisis PCAP file. filter: ip, port, protocol."""
    pcap_file = _validate_path(pcap_file)

    results = []

    # Summary
    summary = _run(f"capinfos {shlex.quote(pcap_file)}", timeout=10)
    if "[ERROR]" not in summary:
        results.append(f"=== PCAP SUMMARY ===\n{summary}")

    # Protocol hierarchy
    proto = _run(f"tshark -r {shlex.quote(pcap_file)} -q -z io,phs", timeout=15)
    if "[ERROR]" not in proto:
        results.append(f"\n=== PROTOCOL HIERARCHY ===\n{proto}")

    # Conversations
    conv = _run(f"tshark -r {shlex.quote(pcap_file)} -q -z conv,tcp | head -30", timeout=15)
    if "[ERROR]" not in conv:
        results.append(f"\n=== TCP CONVERSATIONS ===\n{conv}")

    # Apply filter if provided
    if filter_expr:
        filtered = _run(
            f"tshark -r {shlex.quote(pcap_file)} -Y {shlex.quote(filter_expr)} -T fields -e frame.time -e ip.src -e ip.dst -e tcp.port | head -50",
            timeout=15
        )
        results.append(f"\n=== FILTERED ({filter_expr}) ===\n{filtered}")

    # DNS queries
    dns = _run(f"tshark -r {shlex.quote(pcap_file)} -Y dns.qry.name -T fields -e dns.qry.name 2>/dev/null | sort -u | head -30", timeout=10)
    if dns.strip() and "[ERROR]" not in dns:
        results.append(f"\n=== DNS QUERIES ===\n{dns}")

    # HTTP requests
    http = _run(f"tshark -r {shlex.quote(pcap_file)} -Y http.request -T fields -e http.request.method -e http.host -e http.request.uri 2>/dev/null | head -30", timeout=10)
    if http.strip() and "[ERROR]" not in http:
        results.append(f"\n=== HTTP REQUESTS ===\n{http}")

    return "\n".join(results) if results else "[ERROR] Cannot analyze PCAP file"


# ============================================================
# Evidence Preservation
# ============================================================

def evidence_hash(filepath: str) -> str:
    """Calculate multiple hashes for chain of custody."""
    filepath = _validate_path(filepath)
    results = []

    for alg in ["md5sum", "sha1sum", "sha256sum"]:
        out = _run(f"{alg} {shlex.quote(filepath)}", timeout=30)
        if "[ERROR]" not in out:
            results.append(out.strip())

    # File info
    stat = _run(f"stat {shlex.quote(filepath)}", timeout=5)
    file_type = _run(f"file {shlex.quote(filepath)}", timeout=5)

    result = "=== EVIDENCE HASHES ===\n" + "\n".join(results)
    result += f"\n\n=== FILE INFO ===\n{stat}"
    result += f"\n=== FILE TYPE ===\n{file_type}"
    result += f"\n=== TIMESTAMP ===\n{datetime.now().isoformat()}"

    return result
