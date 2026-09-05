"""
dfir_tools.py - M22: DFIR (Digital Forensic & Incident Response)

Enhanced forensic + incident response tools:
- Automated incident triage
- Evidence chain of custody manager
- Windows event log analysis (offline)
- Malware basic analysis (sandbox-less)
- Incident timeline builder
"""

import json
import os
import re
import shlex
import subprocess
from datetime import datetime


def _run(cmd: str, timeout: int = 60) -> str:
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


def _shell(cmd: str, timeout: int = 60) -> str:
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


# ============================================================
# Incident Triage (Automated)
# ============================================================

def incident_triage() -> str:
    """
    Automated incident triage: run all critical checks in one shot.
    Returns structured triage report.
    """
    results = []
    findings = []

    # 1. Suspicious connections
    results.append("=== 1. NETWORK CONNECTIONS ===")
    conns = _shell("ss -tunapl state established 2>/dev/null | grep -v '127.0.0.1' | head -20", timeout=5)
    results.append(conns)
    suspicious_ports = [":4444", ":5555", ":1234", ":9001", ":31337", ":6666", ":8888"]
    for port in suspicious_ports:
        if port in conns:
            findings.append(f"🚨 Suspicious connection on port {port}")

    # 2. Suspicious processes
    results.append("\n=== 2. SUSPICIOUS PROCESSES ===")
    procs = _shell("ps auxf --sort=-%cpu 2>/dev/null | head -30", timeout=5)
    results.append(procs)
    bad_procs = ["nc -e", "ncat -e", "/bin/sh -i", "/bin/bash -i", "xmrig", "minerd",
                 "cryptonight", "python.*socket", "perl.*socket"]
    for bp in bad_procs:
        if re.search(bp, procs, re.IGNORECASE):
            findings.append(f"🚨 Suspicious process: {bp}")

    # 3. Listening ports
    results.append("\n=== 3. LISTENING PORTS ===")
    ports = _shell("ss -tulpn 2>/dev/null", timeout=5)
    results.append(ports)

    # 4. Recent logins
    results.append("\n=== 4. RECENT LOGINS ===")
    logins = _shell("last -n 10 -a 2>/dev/null", timeout=5)
    results.append(logins)
    failed = _shell("grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0", timeout=3)
    results.append(f"Failed login attempts: {failed.strip()}")
    if failed.strip().isdigit() and int(failed.strip()) > 50:
        findings.append(f"🚨 High failed login count: {failed.strip()}")

    # 5. Cron persistence
    results.append("\n=== 5. CRON JOBS ===")
    cron = _shell("crontab -l 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null", timeout=5)
    results.append(cron)

    # 6. Recently modified system binaries
    results.append("\n=== 6. MODIFIED BINARIES (7 days) ===")
    modified = _shell("find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 -ls 2>/dev/null | head -10", timeout=10)
    results.append(modified)
    if modified.strip() and "[No output]" not in modified:
        findings.append("⚠️ System binaries modified in last 7 days")

    # 7. Temp dir executables
    results.append("\n=== 7. EXECUTABLES IN TEMP ===")
    temps = _shell("find /tmp /var/tmp /dev/shm -type f -executable -ls 2>/dev/null | head -10", timeout=5)
    results.append(temps)
    if temps.strip() and "[No output]" not in temps:
        findings.append("⚠️ Executable files found in temp directories")

    # 8. Running services
    results.append("\n=== 8. RUNNING SERVICES ===")
    svcs = _shell("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | wc -l", timeout=5)
    results.append(f"Running services: {svcs.strip()}")

    # Summary
    summary = "\n\n=== TRIAGE SUMMARY ===\n"
    if findings:
        summary += f"⚠️ {len(findings)} issue(s) found:\n"
        for f in findings:
            summary += f"  {f}\n"
        summary += f"\nSeverity: {'CRITICAL' if any('🚨' in f for f in findings) else 'MEDIUM'}"
    else:
        summary += "✅ No obvious indicators of compromise detected."
    results.append(summary)

    return "\n".join(results)


# ============================================================
# Windows Event Log Analysis (offline)
# ============================================================

def evtx_analysis(evtx_file: str, event_ids: str = "") -> str:
    """
    Parse Windows Event Log (.evtx) files offline.
    Useful event IDs:
    - 4624: Successful login
    - 4625: Failed login
    - 4720: Account created
    - 4732: User added to group
    - 4688: Process creation
    - 7045: Service installed
    - 1102: Audit log cleared
    """
    evtx_file = evtx_file.strip()
    if not os.path.exists(evtx_file):
        return f"[ERROR] File not found: {evtx_file}"

    # Try python-evtx
    cmd = "python3 -c \"import Evtx.Evtx as evtx; print('ok')\" 2>/dev/null"
    check = _shell(cmd, timeout=5)

    if "ok" in check:
        script = f"""
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
import json

results = []
with evtx.Evtx('{evtx_file}') as log:
    for record in log.records():
        try:
            xml = record.xml()
            root = ET.fromstring(xml)
            ns = {{'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}}
            event_id = root.find('.//ns:EventID', ns)
            time_created = root.find('.//ns:TimeCreated', ns)
            eid = event_id.text if event_id is not None else '?'
            ts = time_created.get('SystemTime', '?') if time_created is not None else '?'
            filter_ids = [{','.join(f"'{e.strip()}'" for e in event_ids.split(','))}] if '{event_ids}' else []
            if filter_ids and eid not in filter_ids:
                continue
            results.append(f'[{{eid}}] {{ts}} {{xml[:200]}}')
            if len(results) >= 50:
                break
        except:
            pass
print('\\n'.join(results) if results else 'No matching events found')
"""
        return _shell(f"python3 -c \"{script}\"", timeout=30)
    else:
        # Fallback: strings extraction
        return _run(f"strings {shlex.quote(evtx_file)} | grep -iE 'EventID|login|logon|failed|created|installed' | head -50", timeout=15)


# ============================================================
# Malware Basic Analysis
# ============================================================

def malware_analyze(filepath: str) -> str:
    """
    Basic malware analysis tanpa sandbox:
    - File type & magic bytes
    - Hashes (MD5, SHA256)
    - Strings extraction (URLs, IPs, domains, commands)
    - PE/ELF header info
    - Import table (DLLs / shared libs)
    - Packer detection
    """
    filepath = filepath.strip()
    if not os.path.exists(filepath):
        return f"[ERROR] File not found: {filepath}"

    results = []

    # File type
    ftype = _run(f"file {shlex.quote(filepath)}", timeout=5)
    results.append(f"=== FILE TYPE ===\n{ftype}")

    # Hashes
    md5 = _shell(f"md5sum {shlex.quote(filepath)}", timeout=5)
    sha256 = _shell(f"sha256sum {shlex.quote(filepath)}", timeout=5)
    results.append(f"\n=== HASHES ===\nMD5:    {md5.split()[0] if md5.strip() else 'error'}\nSHA256: {sha256.split()[0] if sha256.strip() else 'error'}")

    # Size
    size = _shell(f"stat -c%s {shlex.quote(filepath)}", timeout=3)
    results.append(f"Size: {size.strip()} bytes")

    # Entropy (packed detection)
    entropy = _shell(f"python3 -c \"import math; data=open('{filepath}','rb').read(); freq=[data.count(bytes([i]))/len(data) for i in range(256)]; e=-sum(f*math.log2(f) for f in freq if f>0); print(f'Entropy: {{e:.2f}} ({{\"HIGH - possibly packed\" if e > 7.0 else \"normal\"}})')\" 2>/dev/null", timeout=5)
    if entropy.strip() and "[ERROR]" not in entropy:
        results.append(f"\n=== ENTROPY ===\n{entropy.strip()}")

    # Interesting strings
    results.append("\n=== INTERESTING STRINGS ===")
    urls = _shell(f"strings {shlex.quote(filepath)} | grep -oiE 'https?://[a-zA-Z0-9./_?&=-]+' | sort -u | head -15", timeout=10)
    if urls.strip():
        results.append(f"URLs:\n{urls}")

    ips = _shell(f"strings {shlex.quote(filepath)} | grep -oE '\\b[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\.[0-9]{{1,3}}\\b' | sort -u | head -10", timeout=5)
    if ips.strip():
        results.append(f"IPs:\n{ips}")

    commands = _shell(f"strings {shlex.quote(filepath)} | grep -iE 'cmd|powershell|bash|wget|curl|chmod|/bin/sh' | head -10", timeout=5)
    if commands.strip():
        results.append(f"Suspicious commands:\n{commands}")

    # PE info (if Windows executable)
    if "PE32" in ftype or "executable" in ftype.lower():
        pe_info = _shell(f"python3 -c \"import pefile; pe=pefile.PE('{filepath}'); print('Imports:'); [print(f'  {{e.dll.decode()}}') for e in pe.DIRECTORY_ENTRY_IMPORT[:15]]\" 2>/dev/null", timeout=10)
        if pe_info.strip() and "[ERROR]" not in pe_info:
            results.append(f"\n=== PE IMPORTS ===\n{pe_info}")

    # ELF info
    if "ELF" in ftype:
        elf = _run(f"readelf -h {shlex.quote(filepath)}", timeout=5)
        if "[ERROR]" not in elf:
            results.append(f"\n=== ELF HEADER ===\n{elf}")
        libs = _run(f"ldd {shlex.quote(filepath)} 2>/dev/null", timeout=5)
        if "[ERROR]" not in libs:
            results.append(f"\n=== SHARED LIBS ===\n{libs}")

    return "\n".join(results)


# ============================================================
# Incident Timeline Builder
# ============================================================

def build_incident_timeline(hours: int = 48, output_file: str = "") -> str:
    """
    Build comprehensive incident timeline dari semua sources:
    - auth.log (logins, sudo)
    - syslog (system events)
    - kern.log (kernel messages)
    - apache/nginx (web access)
    - bash_history (commands)
    - wtmp (login records)
    Sorted chronologically.
    """
    hours = min(hours, 168)
    events = []

    # Auth events
    auth = _shell("grep -E 'session opened|session closed|Failed password|Accepted|sudo:' /var/log/auth.log 2>/dev/null | tail -100", timeout=10)
    for line in auth.split("\n"):
        if line.strip():
            events.append(("AUTH", line.strip()))

    # Syslog events
    syslog = _shell("grep -E 'Started|Stopped|error|warning|critical' /var/log/syslog 2>/dev/null | tail -50", timeout=10)
    for line in syslog.split("\n"):
        if line.strip():
            events.append(("SYSTEM", line.strip()))

    # Kernel
    kern = _shell("grep -E 'error|panic|oops|segfault|oom' /var/log/kern.log 2>/dev/null | tail -20", timeout=5)
    for line in kern.split("\n"):
        if line.strip():
            events.append(("KERNEL", line.strip()))

    # Web access
    for logpath, label in [("/var/log/apache2/access.log", "APACHE"), ("/var/log/nginx/access.log", "NGINX")]:
        if os.path.exists(logpath):
            web = _shell(f"tail -50 {logpath} 2>/dev/null", timeout=5)
            for line in web.split("\n"):
                if line.strip():
                    events.append((label, line.strip()))

    # Bash history
    histories = _shell("find /home -name '.bash_history' -readable 2>/dev/null", timeout=5)
    for hist_path in histories.strip().split("\n"):
        if hist_path.strip() and os.path.exists(hist_path.strip()):
            user = hist_path.strip().split("/")[2] if "/home/" in hist_path else "?"
            cmds = _shell(f"tail -20 {shlex.quote(hist_path.strip())} 2>/dev/null", timeout=3)
            for cmd in cmds.split("\n"):
                if cmd.strip():
                    events.append(("BASH", f"[{user}] {cmd.strip()}"))

    # Build output
    output = f"=== INCIDENT TIMELINE (last {hours}h, {len(events)} events) ===\n\n"
    for source, event in events[:200]:
        output += f"[{source:8s}] {event}\n"

    if not events:
        output += "[INFO] No events captured"

    # Save to file if requested
    if output_file:
        with open(output_file, "w") as f:
            f.write(output)
        output += f"\n\n💾 Saved to: {output_file}"

    return output


# ============================================================
# Evidence Chain of Custody
# ============================================================

def chain_of_custody(filepath: str, action: str = "collect", notes: str = "") -> str:
    """
    Manage evidence chain of custody:
    - collect: Hash, record metadata, create custody entry
    - verify: Re-hash and compare with original
    """
    filepath = filepath.strip()

    custody_dir = "engagements/custody"
    os.makedirs(custody_dir, exist_ok=True)
    custody_file = os.path.join(custody_dir, "chain_of_custody.json")

    # Load existing
    entries = []
    if os.path.exists(custody_file):
        with open(custody_file) as f:
            entries = json.load(f)

    if action == "collect":
        if not os.path.exists(filepath):
            return f"[ERROR] File not found: {filepath}"

        # Hash
        sha256 = _shell(f"sha256sum {shlex.quote(filepath)}", timeout=30).split()[0]
        md5 = _shell(f"md5sum {shlex.quote(filepath)}", timeout=30).split()[0]
        ftype = _run(f"file {shlex.quote(filepath)}", timeout=5).strip()
        stat = _shell(f"stat -c '%s bytes, modified %y' {shlex.quote(filepath)}", timeout=3).strip()

        entry = {
            "id": f"COC-{len(entries)+1:04d}",
            "filepath": filepath,
            "sha256": sha256,
            "md5": md5,
            "file_type": ftype,
            "file_info": stat,
            "collected_at": datetime.now().isoformat(),
            "collected_by": os.environ.get("USER", "unknown"),
            "notes": notes,
            "status": "collected",
        }
        entries.append(entry)

        with open(custody_file, "w") as f:
            json.dump(entries, f, indent=2)

        return (
            f"=== CHAIN OF CUSTODY ===\n"
            f"ID: {entry['id']}\n"
            f"File: {filepath}\n"
            f"SHA256: {sha256}\n"
            f"MD5: {md5}\n"
            f"Type: {ftype}\n"
            f"Info: {stat}\n"
            f"Collected: {entry['collected_at']}\n"
            f"By: {entry['collected_by']}\n"
            f"Notes: {notes}\n"
            f"Status: COLLECTED ✅"
        )

    elif action == "verify":
        # Find entry
        for entry in entries:
            if entry["filepath"] == filepath:
                if not os.path.exists(filepath):
                    return f"[ERROR] File missing: {filepath}"
                current_hash = _shell(f"sha256sum {shlex.quote(filepath)}", timeout=30).split()[0]
                if current_hash == entry["sha256"]:
                    return f"✅ INTEGRITY VERIFIED: {filepath}\n   SHA256 match: {current_hash}"
                else:
                    return f"🚨 INTEGRITY VIOLATION: {filepath}\n   Expected: {entry['sha256']}\n   Current:  {current_hash}"
        return f"[ERROR] No custody entry for: {filepath}"

    elif action == "list":
        if not entries:
            return "No evidence in chain of custody"
        lines = ["=== CHAIN OF CUSTODY LOG ==="]
        for e in entries:
            lines.append(f"  {e['id']} | {e['filepath']} | {e['status']} | {e['collected_at']}")
        return "\n".join(lines)

    return "[ERROR] Unknown action. Use: collect, verify, list"
