"""
tools.py - Tool Registry & Executors

Setiap tool:
1. Menerima parameter yang sudah divalidasi oleh policy engine
2. Menerjemahkan parameter menjadi command Kali yang tepat
3. Mengeksekusi command
4. Mengembalikan raw output

LLM TIDAK menentukan command. Tool executor yang menentukan.
"""

import json as _json
import re
import shlex
import subprocess
from collections.abc import Callable
from typing import Any

from quarr.core.exceptions import QuarrError, ToolNotFoundError
from quarr.core.models import RiskLevel

# === Integration delegation helper (Phase 2) ===

def _summarize(result) -> str:
    """Convert a ToolResult into the human-readable string handlers must return."""
    header = f"[{result.tool_name}] {'OK' if result.success else 'FAILED'}"
    if result.error:
        header += f" — {result.error}"
    parsed = _json.dumps(result.parsed, indent=2, default=str)
    return f"{header}\n{parsed}"


def _delegate(integration, **kwargs) -> str:
    """
    Run a ToolIntegration, returning a summary string. On a missing binary,
    return a friendly not-installed message instead of raising (Req 8.3).
    """
    try:
        result = integration.run(**kwargs)
    except ToolNotFoundError as e:
        binary = e.context.get("tool", getattr(integration, "binary_name", "tool"))
        return f"[TOOL NOT INSTALLED] {binary} is not available on this host."
    except QuarrError as e:
        return f"[ERROR] {e}"
    return _summarize(result)


# === Tool Metadata ===

class ToolMeta:
    """Metadata untuk setiap tool."""
    def __init__(
        self,
        name: str,
        description: str,
        category: str,
        risk: RiskLevel,
        requires_scope: bool,
        handler: Callable,
        parameters: dict[str, Any],
        timeout: int = 180,
    ):
        self.name = name
        self.description = description
        self.category = category
        self.risk = risk
        self.requires_scope = requires_scope
        self.handler = handler
        self.parameters = parameters
        self.timeout = timeout


# === Utility ===

def _run_command(cmd: str, timeout: int = 180) -> str:
    """Execute a shell command safely."""
    try:
        result = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR] {result.stderr}"
        return output if output.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd.split()[0]}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def _validate_target(target: str) -> str:
    """Sanitize target input (hostname/IP/CIDR)."""
    target = target.strip()
    target = re.sub(r'^https?://', '', target)
    target = target.rstrip('/')
    if not re.match(r'^[a-zA-Z0-9._\-/]+$', target):
        raise ValueError(f"Invalid target format: {target}")
    return target


def _validate_url(url: str) -> str:
    """Sanitize URL target, pastikan ada scheme."""
    url = url.strip()
    if not re.match(r'^https?://', url):
        url = f"https://{url}"
    return url


def _validate_domain(domain: str) -> str:
    """Sanitize domain."""
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')
    domain = domain.split('/')[0]  # ambil domain saja
    if not re.match(r'^[a-zA-Z0-9._\-]+$', domain):
        raise ValueError(f"Invalid domain format: {domain}")
    return domain


# ============================================================
# PHASE 1: RECONNAISSANCE
# ============================================================

def target_scope_check(target: str) -> str:
    """Verifikasi konektivitas target (ping)."""
    target = _validate_target(target)
    cmd = f"ping -c 3 -W 2 {shlex.quote(target)}"
    return _run_command(cmd, timeout=15)


def network_discovery(target: str) -> str:
    """Discover hosts dalam scope (nmap ping scan)."""
    from quarr.tools.integrations.nmap import NmapIntegration
    return _delegate(NmapIntegration(mode="discovery"), target=target)


def service_enumeration(target: str, profile: str = "basic") -> str:
    """Enumerasi services pada host."""
    from quarr.tools.integrations.nmap import NmapIntegration
    ports = None if profile == "basic" else "1-65535"
    return _delegate(NmapIntegration(mode="service"), target=target, ports=ports)


def subdomain_enum(target: str, mode: str = "passive") -> str:
    """Enumerasi subdomain."""
    domain = _validate_domain(target)
    if mode == "passive":
        cmd = f"subfinder -d {shlex.quote(domain)} -silent"
        timeout = 120
    elif mode == "active":
        cmd = f"amass enum -passive -d {shlex.quote(domain)} -timeout 3"
        timeout = 180
    else:
        return f"[ERROR] Unknown mode: {mode}. Use 'passive' or 'active'."
    return _run_command(cmd, timeout=timeout)


def web_fingerprint(target: str) -> str:
    """Technology fingerprinting (tech stack, framework, CMS)."""
    url = _validate_url(target)
    cmd = f"whatweb {shlex.quote(url)} --color=never -v"
    return _run_command(cmd, timeout=30)


# ============================================================
# PHASE 2: DISCOVERY & ENUMERATION
# ============================================================

def web_content_discovery(target: str, wordlist: str = "common", mode: str = "dir") -> str:
    """
    Directory/file brute-force.
    wordlist: "common", "medium", "large", "api"
    mode: "dir" (directories) atau "dns" (subdomain via dns)
    """
    url = _validate_url(target)

    wordlists = {
        "common": "/usr/share/wordlists/dirb/common.txt",
        "medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "large": "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
        "api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    }
    # Restrict wordlist to known presets so an arbitrary filesystem path cannot
    # be passed as a tool argument.
    if wordlist not in wordlists:
        return f"[ERROR] Unknown wordlist '{wordlist}'. Use: {', '.join(wordlists)}"
    wl_path = wordlists[wordlist]

    # Validate mode against the fixed subcommand set (prevents flag injection).
    if mode not in ("dir", "dns"):
        return "[ERROR] Invalid mode. Use 'dir' or 'dns'."

    if mode == "dns":
        # gobuster's dns subcommand targets a DOMAIN via -d, not a URL via -u.
        domain = _validate_domain(target)
        cmd = f"gobuster dns -d {shlex.quote(domain)} -w {shlex.quote(wl_path)} -t 30 -q --no-error"
    else:
        cmd = f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wl_path)} -t 30 -q --no-error"
    return _run_command(cmd, timeout=180)


def web_crawl(target: str) -> str:
    """Crawl website untuk menemukan endpoints dan links."""
    url = _validate_url(target)
    cmd = f"katana -u {shlex.quote(url)} -d 3 -silent -jc"
    return _run_command(cmd, timeout=120)


def parameter_discovery(target: str) -> str:
    """Temukan hidden parameters pada URL."""
    url = _validate_url(target)
    cmd = f"arjun -u {shlex.quote(url)} --stable"
    return _run_command(cmd, timeout=120)


# ============================================================
# PHASE 3: VULNERABILITY SCANNING
# ============================================================

def vulnerability_scan(target: str, severity: str = "critical,high") -> str:
    """Automated vulnerability scanning (Nuclei)."""
    url = _validate_url(target)
    # Validate severity strictly: only known levels, comma-separated. Prevents
    # injecting extra nuclei flags (e.g. "-t http://evil/x.yaml") via this arg.
    allowed_sev = {"critical", "high", "medium", "low", "info", "unknown"}
    levels = [s.strip().lower() for s in severity.split(",") if s.strip()]
    if not levels or any(lvl not in allowed_sev for lvl in levels):
        return "[ERROR] Invalid severity. Use any of: critical,high,medium,low,info"
    severity = ",".join(levels)
    cmd = f"nuclei -u {shlex.quote(url)} -severity {shlex.quote(severity)} -silent -jsonl"
    return _run_command(cmd, timeout=300)


def web_vuln_scan(target: str) -> str:
    """Web server vulnerability scan (Nikto)."""
    from quarr.tools.integrations.nikto import NiktoIntegration
    return _delegate(NiktoIntegration(), target=target)


def ssl_scan(target: str) -> str:
    """Scan konfigurasi SSL/TLS."""
    from quarr.tools.integrations.sslscan import SSLScanIntegration
    return _delegate(SSLScanIntegration(), target=target)


def waf_detection(target: str) -> str:
    """Deteksi Web Application Firewall."""
    url = _validate_url(target)
    cmd = f"wafw00f {shlex.quote(url)}"
    return _run_command(cmd, timeout=30)


def cms_scan(target: str) -> str:
    """WordPress vulnerability scan (jika CMS WordPress)."""
    url = _validate_url(target)
    cmd = f"wpscan --url {shlex.quote(url)} --enumerate vp,vt,u --no-banner --format cli"
    return _run_command(cmd, timeout=180)


# ============================================================
# PHASE 4: EXPLOITATION
# ============================================================

def sqli_scan(target: str, parameter: str = "") -> str:
    """SQL Injection scanner."""
    from quarr.tools.integrations.sqlmap import SqlmapIntegration
    return _delegate(SqlmapIntegration(), target=target, level=1, risk=1)


def xss_scan(target: str) -> str:
    """XSS vulnerability scanner."""
    url = _validate_url(target)
    cmd = f"dalfox url {shlex.quote(url)} --silence --no-color"
    return _run_command(cmd, timeout=120)


def command_injection_scan(target: str) -> str:
    """Command injection scanner."""
    url = _validate_url(target)
    cmd = f"commix -u {shlex.quote(url)} --batch --level=2"
    return _run_command(cmd, timeout=120)


def bruteforce_login(target: str, service: str = "ssh",
                     username: str = "admin",
                     wordlist: str = "default") -> str:
    """Brute-force password attack."""
    target_clean = _validate_target(target)

    allowed_services = ["ssh", "ftp", "http-get", "mysql", "rdp", "smb"]
    if service not in allowed_services:
        return f"[ERROR] Service harus salah satu dari: {', '.join(allowed_services)}"

    wordlists = {
        "default": "/usr/share/wordlists/rockyou.txt",
        "small": "/usr/share/seclists/Passwords/Common-Credentials/top-1000.txt",
        "medium": "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    }
    wl_path = wordlists.get(wordlist, wordlist)

    cmd = (
        f"hydra -l {shlex.quote(username)} -P {shlex.quote(wl_path)} "
        f"{shlex.quote(target_clean)} {service} -t 4 -f -V -I"
    )
    return _run_command(cmd, timeout=180)


def exploit_search(query: str) -> str:
    """Cari exploit di ExploitDB."""
    cmd = f"searchsploit {shlex.quote(query)} --json"
    return _run_command(cmd, timeout=15)


# ============================================================
# PHASE 5: NETWORK ENUMERATION (SMB, SNMP, etc)
# ============================================================

def smb_enum(target: str) -> str:
    """Full SMB/NetBIOS enumeration."""
    target = _validate_target(target)
    cmd = f"enum4linux -a {shlex.quote(target)}"
    return _run_command(cmd, timeout=120)


def dns_enum(target: str) -> str:
    """DNS enumeration."""
    domain = _validate_domain(target)
    cmd = f"dnsenum {shlex.quote(domain)} --noreverse"
    return _run_command(cmd, timeout=60)


def snmp_enum(target: str, community: str = "public") -> str:
    """SNMP enumeration."""
    target = _validate_target(target)
    cmd = f"snmpwalk -v2c -c {shlex.quote(community)} {shlex.quote(target)}"
    return _run_command(cmd, timeout=60)


# ============================================================
# TOOL REGISTRY
# ============================================================

TOOL_REGISTRY: dict[str, ToolMeta] = {}


def _register(name, description, category, risk, requires_scope,
              handler, parameters, timeout=180):
    """Helper untuk register tool."""
    TOOL_REGISTRY[name] = ToolMeta(
        name=name,
        description=description,
        category=category,
        risk=risk,
        requires_scope=requires_scope,
        handler=handler,
        parameters=parameters,
        timeout=timeout,
    )


# --- Phase 1: Reconnaissance ---

_register(
    "target_scope_check",
    "Verify target reachability within authorized scope.",
    "recon", RiskLevel.LOW, True,
    target_scope_check,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP or hostname."}
    }, "required": ["target"]},
    timeout=15,
)

_register(
    "network_discovery",
    "Discover live hosts within the authorized scope using ping scan.",
    "recon", RiskLevel.LOW, True,
    network_discovery,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP, hostname, or CIDR range."}
    }, "required": ["target"]},
    timeout=120,
)

_register(
    "service_enumeration",
    "Enumerate network services and versions on a host.",
    "recon", RiskLevel.LOW, True,
    service_enumeration,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP or hostname."},
        "profile": {"type": "string", "enum": ["basic", "service_detection"],
                     "description": "'basic' = top 100 ports. 'service_detection' = all ports with scripts."}
    }, "required": ["target", "profile"]},
    timeout=600,
)

_register(
    "subdomain_enum",
    "Enumerate subdomains of a target domain.",
    "recon", RiskLevel.LOW, True,
    subdomain_enum,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target domain (e.g., target.com)."},
        "mode": {"type": "string", "enum": ["passive", "active"],
                  "description": "'passive' = subfinder (fast). 'active' = amass (thorough)."}
    }, "required": ["target"]},
    timeout=180,
)

_register(
    "web_fingerprint",
    "Identify web technologies, frameworks, CMS, and server software.",
    "recon", RiskLevel.LOW, True,
    web_fingerprint,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL or hostname."}
    }, "required": ["target"]},
    timeout=30,
)

_register(
    "waf_detection",
    "Detect Web Application Firewall protecting the target.",
    "recon", RiskLevel.LOW, True,
    waf_detection,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL."}
    }, "required": ["target"]},
    timeout=30,
)

# --- Phase 2: Discovery ---

_register(
    "web_content_discovery",
    "Brute-force directories and files on a web server.",
    "discovery", RiskLevel.LOW, True,
    web_content_discovery,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL."},
        "wordlist": {"type": "string", "enum": ["common", "medium", "large", "api"],
                      "description": "Wordlist size. 'common' = fast, 'api' = API endpoints."},
        "mode": {"type": "string", "enum": ["dir", "dns"],
                  "description": "'dir' = directory brute-force. 'dns' = subdomain brute-force."}
    }, "required": ["target"]},
    timeout=180,
)

_register(
    "web_crawl",
    "Crawl a website to discover endpoints, links, and JavaScript files.",
    "discovery", RiskLevel.LOW, True,
    web_crawl,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL to crawl."}
    }, "required": ["target"]},
    timeout=120,
)

_register(
    "parameter_discovery",
    "Discover hidden HTTP parameters on a URL endpoint.",
    "discovery", RiskLevel.LOW, True,
    parameter_discovery,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL endpoint."}
    }, "required": ["target"]},
    timeout=120,
)

# --- Phase 3: Vulnerability Scanning ---

_register(
    "vulnerability_scan",
    "Automated vulnerability scanning using Nuclei templates (CVEs, misconfigs, exposures).",
    "vuln_scan", RiskLevel.MEDIUM, True,
    vulnerability_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL."},
        "severity": {"type": "string",
                      "description": "Comma-separated severity filter: critical,high,medium,low,info."}
    }, "required": ["target"]},
    timeout=300,
)

_register(
    "web_vuln_scan",
    "Web server vulnerability scan (outdated software, dangerous methods, misconfigs).",
    "vuln_scan", RiskLevel.MEDIUM, True,
    web_vuln_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL."}
    }, "required": ["target"]},
    timeout=200,
)

_register(
    "ssl_scan",
    "Audit SSL/TLS configuration (weak ciphers, expired certs, protocol versions).",
    "vuln_scan", RiskLevel.LOW, True,
    ssl_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target hostname or IP (port 443 default)."}
    }, "required": ["target"]},
    timeout=30,
)

_register(
    "cms_scan",
    "WordPress vulnerability scan (plugins, themes, users).",
    "vuln_scan", RiskLevel.MEDIUM, True,
    cms_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "WordPress site URL."}
    }, "required": ["target"]},
    timeout=180,
)

# --- Phase 4: Exploitation ---

_register(
    "sqli_scan",
    "Test for SQL injection vulnerabilities on a URL with parameters.",
    "exploit", RiskLevel.HIGH, True,
    sqli_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL with query parameters (e.g., https://site.com/page?id=1)."},
        "parameter": {"type": "string", "description": "Specific parameter to test (optional, tests all if empty)."}
    }, "required": ["target"]},
    timeout=180,
)

_register(
    "xss_scan",
    "Scan for Cross-Site Scripting (XSS) vulnerabilities.",
    "exploit", RiskLevel.HIGH, True,
    xss_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL with parameters to test for XSS."}
    }, "required": ["target"]},
    timeout=120,
)

_register(
    "command_injection_scan",
    "Test for OS command injection vulnerabilities.",
    "exploit", RiskLevel.HIGH, True,
    command_injection_scan,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target URL with parameters."}
    }, "required": ["target"]},
    timeout=120,
)

_register(
    "bruteforce_login",
    "Brute-force password attack on a network service.",
    "exploit", RiskLevel.HIGH, True,
    bruteforce_login,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP or hostname."},
        "service": {"type": "string", "enum": ["ssh", "ftp", "http-get", "mysql", "rdp", "smb"],
                     "description": "Service to brute-force."},
        "username": {"type": "string", "description": "Username to test."},
        "wordlist": {"type": "string", "enum": ["default", "small", "medium"],
                      "description": "'small' = top 1000. 'default' = rockyou.txt."}
    }, "required": ["target", "service"]},
    timeout=180,
)

_register(
    "exploit_search",
    "Search ExploitDB for known exploits matching a query (software name, CVE, etc).",
    "exploit", RiskLevel.LOW, False,
    exploit_search,
    {"type": "object", "properties": {
        "query": {"type": "string", "description": "Search query (e.g., 'Apache 2.4.49', 'CVE-2021-41773')."}
    }, "required": ["query"]},
    timeout=15,
)

# --- Phase 5: Network Enumeration ---

_register(
    "smb_enum",
    "Full SMB/NetBIOS enumeration (shares, users, policies).",
    "network_enum", RiskLevel.MEDIUM, True,
    smb_enum,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP or hostname."}
    }, "required": ["target"]},
    timeout=120,
)

_register(
    "dns_enum",
    "DNS enumeration (records, zone transfer attempt).",
    "network_enum", RiskLevel.LOW, True,
    dns_enum,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target domain."}
    }, "required": ["target"]},
    timeout=60,
)

_register(
    "snmp_enum",
    "SNMP enumeration (system info, interfaces, processes).",
    "network_enum", RiskLevel.LOW, True,
    snmp_enum,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP."},
        "community": {"type": "string", "description": "SNMP community string (default: public)."}
    }, "required": ["target"]},
    timeout=60,
)


# ============================================================
# M8: MOBILE APPLICATION PENTEST
# ============================================================

from quarr.tools.mobile import (  # noqa: E402 (intentional sectioned import before domain registration)
    adb_app_info,
    adb_device_check,
    adb_logcat_check,
    adb_storage_check,
    apk_cert_check,
    apk_decompile,
    apk_manifest_analysis,
    apk_network_config,
    apk_secrets_scan,
    frida_ssl_bypass,
    objection_explore,
)

# --- Static Analysis (tanpa device) ---

_register(
    "apk_decompile",
    "Decompile APK file using apktool (resources/smali) and jadx (Java source). Returns decompiled directory paths.",
    "mobile_static", RiskLevel.LOW, False,
    apk_decompile,
    {"type": "object", "properties": {
        "apk_path": {"type": "string", "description": "Path to APK file on disk."},
        "output_dir": {"type": "string", "description": "Output directory (default: /tmp/quarr_apk)."}
    }, "required": ["apk_path"]},
    timeout=180,
)

_register(
    "apk_secrets_scan",
    "Scan decompiled APK source for hardcoded secrets: API keys, passwords, tokens, private keys, Firebase configs, AWS credentials. Also extracts API endpoint URLs.",
    "mobile_static", RiskLevel.LOW, False,
    apk_secrets_scan,
    {"type": "object", "properties": {
        "directory": {"type": "string", "description": "Directory of decompiled APK source code."}
    }, "required": ["directory"]},
    timeout=30,
)

_register(
    "apk_manifest_analysis",
    "Deep analysis of AndroidManifest.xml: permissions, exported components, backup/debuggable flags, deeplinks, SDK versions, network security config.",
    "mobile_static", RiskLevel.LOW, False,
    apk_manifest_analysis,
    {"type": "object", "properties": {
        "apk_decoded_dir": {"type": "string", "description": "Directory of apktool-decoded APK (containing AndroidManifest.xml)."}
    }, "required": ["apk_decoded_dir"]},
    timeout=10,
)

_register(
    "apk_network_config",
    "Analyze network_security_config.xml: cleartext traffic, certificate pinning, custom trust anchors, debug overrides.",
    "mobile_static", RiskLevel.LOW, False,
    apk_network_config,
    {"type": "object", "properties": {
        "apk_decoded_dir": {"type": "string", "description": "Directory of apktool-decoded APK."}
    }, "required": ["apk_decoded_dir"]},
    timeout=10,
)

_register(
    "apk_cert_check",
    "Check APK signing certificate: debug vs release, signature algorithm strength, V1/V2/V3 signing scheme.",
    "mobile_static", RiskLevel.LOW, False,
    apk_cert_check,
    {"type": "object", "properties": {
        "apk_path": {"type": "string", "description": "Path to APK file."}
    }, "required": ["apk_path"]},
    timeout=15,
)

# --- Dynamic Analysis (perlu ADB / device) ---

_register(
    "adb_device_check",
    "Check if any Android device or emulator is connected via ADB.",
    "mobile_dynamic", RiskLevel.LOW, False,
    adb_device_check,
    {"type": "object", "properties": {}, "required": []},
    timeout=10,
)

_register(
    "adb_app_info",
    "Get detailed info about an installed Android app: version, permissions, data directories, flags.",
    "mobile_dynamic", RiskLevel.LOW, False,
    adb_app_info,
    {"type": "object", "properties": {
        "package": {"type": "string", "description": "Android package name (e.g., com.example.app)."}
    }, "required": ["package"]},
    timeout=15,
)

_register(
    "adb_storage_check",
    "Check insecure data storage on device: SharedPreferences (plaintext secrets), SQLite databases (unencrypted), external storage. Requires root or debuggable app.",
    "mobile_dynamic", RiskLevel.MEDIUM, False,
    adb_storage_check,
    {"type": "object", "properties": {
        "package": {"type": "string", "description": "Android package name."}
    }, "required": ["package"]},
    timeout=30,
)

_register(
    "adb_logcat_check",
    "Check for sensitive data leaked in Android logcat: credentials, tokens, PII, debug info.",
    "mobile_dynamic", RiskLevel.LOW, False,
    adb_logcat_check,
    {"type": "object", "properties": {
        "package": {"type": "string", "description": "Android package name."}
    }, "required": ["package"]},
    timeout=15,
)

_register(
    "frida_ssl_bypass",
    "Bypass SSL certificate pinning using Frida. Injects universal SSL bypass script. Requires frida-server running on device.",
    "mobile_dynamic", RiskLevel.HIGH, False,
    frida_ssl_bypass,
    {"type": "object", "properties": {
        "package": {"type": "string", "description": "Android package name to bypass SSL pinning."}
    }, "required": ["package"]},
    timeout=20,
)

_register(
    "objection_explore",
    "Frida-based mobile app exploration via Objection. Commands: env, android sslpinning disable, android root disable, android hooking list classes, android keystore list.",
    "mobile_dynamic", RiskLevel.MEDIUM, False,
    objection_explore,
    {"type": "object", "properties": {
        "package": {"type": "string", "description": "Android package name."},
        "command": {"type": "string", "description": "Objection command (e.g., 'env', 'android sslpinning disable', 'android root disable')."}
    }, "required": ["package", "command"]},
    timeout=30,
)


# ============================================================
# M12: ACTIVE DIRECTORY PENTEST
# ============================================================

from quarr.tools.active_directory import (  # noqa: E402 (intentional sectioned import before domain registration)
    bloodhound_collect,
    hash_crack,
    kerberos_asrep_roast,
    kerberos_kerberoast,
    ldap_domain_dump,
    ldap_search,
    password_spray,
    psexec,
    rpc_enum,
    secrets_dump,
    wmiexec,
)

_register(
    "kerberos_asrep_roast",
    "AS-REP Roasting: find AD users without Kerberos pre-authentication and extract hashes for offline cracking.",
    "ad_attack", RiskLevel.HIGH, True,
    kerberos_asrep_roast,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Domain Controller IP."},
        "domain": {"type": "string", "description": "AD domain name (e.g., corp.local)."},
        "usersfile": {"type": "string", "description": "File with usernames (optional)."}
    }, "required": ["target", "domain"]},
    timeout=60,
)

_register(
    "kerberos_kerberoast",
    "Kerberoasting: extract service ticket hashes from AD for offline cracking.",
    "ad_attack", RiskLevel.HIGH, True,
    kerberos_kerberoast,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Domain Controller IP."},
        "domain": {"type": "string", "description": "AD domain."},
        "username": {"type": "string", "description": "Valid AD username."},
        "password": {"type": "string", "description": "Password for the user."}
    }, "required": ["target", "domain", "username", "password"]},
    timeout=60,
)

_register(
    "secrets_dump",
    "Dump SAM/NTDS password hashes from Domain Controller or workstation using Impacket.",
    "ad_attack", RiskLevel.CRITICAL, True,
    secrets_dump,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP."},
        "username": {"type": "string", "description": "Username with admin privileges."},
        "password": {"type": "string", "description": "Password or NTLM hash."},
        "domain": {"type": "string", "description": "AD domain (optional)."}
    }, "required": ["target", "username", "password"]},
    timeout=120,
)

_register(
    "psexec",
    "Remote command execution on Windows via PsExec (SMB-based). Requires admin credentials.",
    "ad_attack", RiskLevel.CRITICAL, True,
    psexec,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target Windows IP."},
        "username": {"type": "string", "description": "Admin username."},
        "password": {"type": "string", "description": "Password or NTLM hash."},
        "command": {"type": "string", "description": "Command to execute (default: whoami)."},
        "domain": {"type": "string", "description": "AD domain (optional)."}
    }, "required": ["target", "username", "password"]},
    timeout=30,
)

_register(
    "wmiexec",
    "Remote command execution on Windows via WMI. Stealthier than PsExec.",
    "ad_attack", RiskLevel.CRITICAL, True,
    wmiexec,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target Windows IP."},
        "username": {"type": "string", "description": "Admin username."},
        "password": {"type": "string", "description": "Password or NTLM hash."},
        "command": {"type": "string", "description": "Command to execute."},
        "domain": {"type": "string", "description": "AD domain (optional)."}
    }, "required": ["target", "username", "password"]},
    timeout=30,
)

_register(
    "ldap_search",
    "LDAP enumeration: discover AD users, groups, computers.",
    "ad_enum", RiskLevel.LOW, True,
    ldap_search,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Domain Controller IP."},
        "base_dn": {"type": "string", "description": "Base DN (auto-generated if empty)."},
        "username": {"type": "string", "description": "Bind username (optional)."},
        "password": {"type": "string", "description": "Bind password (optional)."}
    }, "required": ["target"]},
    timeout=30,
)

_register(
    "ldap_domain_dump",
    "Dump full LDAP domain information (users, groups, computers, trusts, policies).",
    "ad_enum", RiskLevel.MEDIUM, True,
    ldap_domain_dump,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Domain Controller IP."},
        "username": {"type": "string", "description": "AD username."},
        "password": {"type": "string", "description": "Password."},
        "domain": {"type": "string", "description": "AD domain."}
    }, "required": ["target", "username", "password"]},
    timeout=60,
)

_register(
    "bloodhound_collect",
    "Collect AD data for BloodHound analysis (users, groups, sessions, ACLs, trusts).",
    "ad_enum", RiskLevel.MEDIUM, True,
    bloodhound_collect,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Domain Controller IP."},
        "domain": {"type": "string", "description": "AD domain."},
        "username": {"type": "string", "description": "AD username."},
        "password": {"type": "string", "description": "Password."}
    }, "required": ["target", "domain", "username", "password"]},
    timeout=120,
)

_register(
    "rpc_enum",
    "RPC enumeration: users, groups, shares via rpcclient. Supports null session.",
    "ad_enum", RiskLevel.LOW, True,
    rpc_enum,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Target IP."},
        "username": {"type": "string", "description": "Username (empty for null session)."},
        "password": {"type": "string", "description": "Password (empty for null session)."}
    }, "required": ["target"]},
    timeout=30,
)

_register(
    "password_spray",
    "Password spray attack against AD using CrackMapExec.",
    "ad_attack", RiskLevel.HIGH, True,
    password_spray,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Domain Controller IP."},
        "domain": {"type": "string", "description": "AD domain."},
        "userlist": {"type": "string", "description": "File path with usernames."},
        "password": {"type": "string", "description": "Password to spray."}
    }, "required": ["target", "domain", "userlist", "password"]},
    timeout=120,
)

_register(
    "hash_crack",
    "Crack password hashes with hashcat. Supports MD5, NTLM, sha512crypt, Kerberoast.",
    "ad_attack", RiskLevel.LOW, False,
    hash_crack,
    {"type": "object", "properties": {
        "hash_file": {"type": "string", "description": "Path to file containing hashes."},
        "mode": {"type": "string", "description": "Hashcat mode: 0=MD5, 1000=NTLM, 1800=sha512crypt, 13100=kerberoast."},
        "wordlist": {"type": "string", "description": "Wordlist path (default: rockyou.txt)."}
    }, "required": ["hash_file", "mode"]},
    timeout=300,
)


# ============================================================
# M19: BLUE TEAM — DEFENSE & MONITORING
# ============================================================

from quarr.tools.blue_team import (  # noqa: E402 (intentional sectioned import before domain registration)
    active_connections,
    cron_audit,
    file_integrity_check,
    firewall_block,
    firewall_status,
    firewall_unblock,
    log_analysis,
    port_audit,
    process_monitor,
    service_audit,
    user_audit,
)

_register("firewall_status", "Check firewall rules (iptables + UFW status).",
    "blue_defense", RiskLevel.LOW, False, firewall_status,
    {"type": "object", "properties": {}, "required": []}, timeout=10)

_register("firewall_block", "Block an IP address in the firewall.",
    "blue_defense", RiskLevel.MEDIUM, False, firewall_block,
    {"type": "object", "properties": {
        "ip_address": {"type": "string", "description": "IP to block (e.g., 1.2.3.4 or 1.2.3.0/24)."}
    }, "required": ["ip_address"]}, timeout=5)

_register("firewall_unblock", "Remove IP block from firewall.",
    "blue_defense", RiskLevel.MEDIUM, False, firewall_unblock,
    {"type": "object", "properties": {
        "ip_address": {"type": "string", "description": "IP to unblock."}
    }, "required": ["ip_address"]}, timeout=5)

_register("log_analysis", "Analyze system logs: auth, syslog, kern, ufw, fail2ban, apache, nginx.",
    "blue_defense", RiskLevel.LOW, False, log_analysis,
    {"type": "object", "properties": {
        "log_type": {"type": "string", "enum": ["auth", "syslog", "kern", "ufw", "fail2ban", "apache", "nginx"], "description": "Log type to analyze."},
        "lines": {"type": "integer", "description": "Number of lines (default 100, max 500)."},
        "filter_pattern": {"type": "string", "description": "Optional grep filter pattern."}
    }, "required": ["log_type"]}, timeout=10)

_register("active_connections", "Check active network connections. Filter: all, established, listening, suspicious.",
    "blue_defense", RiskLevel.LOW, False, active_connections,
    {"type": "object", "properties": {
        "filter_type": {"type": "string", "enum": ["all", "established", "listening", "suspicious"], "description": "Connection filter."}
    }, "required": []}, timeout=10)

_register("port_audit", "Audit all listening ports — detect backdoors and unauthorized services.",
    "blue_defense", RiskLevel.LOW, False, port_audit,
    {"type": "object", "properties": {}, "required": []}, timeout=10)

_register("process_monitor", "Monitor running processes — detect reverse shells, miners, suspicious activity.",
    "blue_defense", RiskLevel.LOW, False, process_monitor,
    {"type": "object", "properties": {
        "filter_pattern": {"type": "string", "description": "Optional filter (e.g., 'python', 'nc', 'miner')."}
    }, "required": []}, timeout=10)

_register("service_audit", "Audit systemd services: running + enabled at boot.",
    "blue_defense", RiskLevel.LOW, False, service_audit,
    {"type": "object", "properties": {}, "required": []}, timeout=10)

_register("user_audit", "Audit users: active sessions, login history, failed logins, sudo access, shell users.",
    "blue_defense", RiskLevel.LOW, False, user_audit,
    {"type": "object", "properties": {}, "required": []}, timeout=15)

_register("cron_audit", "Audit cron jobs — detect persistence mechanisms.",
    "blue_defense", RiskLevel.LOW, False, cron_audit,
    {"type": "object", "properties": {}, "required": []}, timeout=15)

_register("file_integrity_check", "Check files modified in last N days. Detect unauthorized changes, SUID binaries.",
    "blue_defense", RiskLevel.LOW, False, file_integrity_check,
    {"type": "object", "properties": {
        "directory": {"type": "string", "description": "Directory to check (default: /usr/bin)."},
        "days": {"type": "integer", "description": "Check files modified in last N days (default: 7)."}
    }, "required": []}, timeout=15)


# ============================================================
# M20: THREAT HUNTING & DETECTION
# ============================================================

from quarr.tools.threat_hunting import (  # noqa: E402 (intentional sectioned import before domain registration)
    baseline_compare,
    dns_anomaly_check,
    hash_verify,
    ioc_search,
    network_capture,
    rootkit_scan,
    suspicious_files,
    yara_scan,
)

_register("ioc_search", "Search for Indicators of Compromise (IOC) on the system: IP, domain, hash, filename, string.",
    "threat_hunting", RiskLevel.LOW, False, ioc_search,
    {"type": "object", "properties": {
        "ioc_type": {"type": "string", "enum": ["ip", "domain", "hash", "filename", "string"], "description": "IOC type."},
        "value": {"type": "string", "description": "IOC value to search for."}
    }, "required": ["ioc_type", "value"]}, timeout=30)

_register("suspicious_files", "Find suspicious files: recently created, hidden, executable in temp directories.",
    "threat_hunting", RiskLevel.LOW, False, suspicious_files,
    {"type": "object", "properties": {
        "directory": {"type": "string", "description": "Directory to scan (default: /tmp)."},
        "days": {"type": "integer", "description": "Look back N days (default: 3)."}
    }, "required": []}, timeout=15)

_register("rootkit_scan", "Scan for rootkits using chkrootkit and rkhunter.",
    "threat_hunting", RiskLevel.LOW, False, rootkit_scan,
    {"type": "object", "properties": {}, "required": []}, timeout=180)

_register("yara_scan", "Scan files with YARA rules for malware detection.",
    "threat_hunting", RiskLevel.LOW, False, yara_scan,
    {"type": "object", "properties": {
        "directory": {"type": "string", "description": "Directory to scan."},
        "rules_path": {"type": "string", "description": "Path to YARA rules (optional, auto-detect)."}
    }, "required": ["directory"]}, timeout=60)

_register("network_capture", "Capture network packets for analysis.",
    "threat_hunting", RiskLevel.LOW, False, network_capture,
    {"type": "object", "properties": {
        "interface": {"type": "string", "description": "Network interface (default: eth0)."},
        "count": {"type": "integer", "description": "Number of packets (default: 100, max 500)."},
        "filter_expr": {"type": "string", "description": "Capture filter (e.g., 'port 80', 'host 1.2.3.4')."}
    }, "required": []}, timeout=15)

_register("dns_anomaly_check", "Detect DNS anomalies: tunneling, DGA domains, unusual TXT queries.",
    "threat_hunting", RiskLevel.LOW, False, dns_anomaly_check,
    {"type": "object", "properties": {
        "interface": {"type": "string", "description": "Network interface (default: eth0)."}
    }, "required": []}, timeout=15)

_register("hash_verify", "Calculate SHA256 hash of a file for integrity verification.",
    "threat_hunting", RiskLevel.LOW, False, hash_verify,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "File path to hash."}
    }, "required": ["filepath"]}, timeout=30)

_register("baseline_compare", "Compare current file state vs baseline. Creates baseline if none exists.",
    "threat_hunting", RiskLevel.LOW, False, baseline_compare,
    {"type": "object", "properties": {
        "directory": {"type": "string", "description": "Directory to compare (default: /usr/bin)."},
        "baseline_file": {"type": "string", "description": "Baseline file path (auto-generated if empty)."}
    }, "required": []}, timeout=30)


# ============================================================
# M21: DIGITAL FORENSIC
# ============================================================

from quarr.tools.forensic import (  # noqa: E402 (intentional sectioned import before domain registration)
    binwalk_analysis,
    browser_forensic,
    disk_image,
    evidence_hash,
    file_recovery,
    log_timeline,
    memory_analysis,
    memory_dump,
    metadata_extract,
    pcap_analysis,
    string_extract,
)

_register("disk_image", "Create forensic disk image with hash verification.",
    "forensic", RiskLevel.LOW, False, disk_image,
    {"type": "object", "properties": {
        "source": {"type": "string", "description": "Source device or file (e.g., /dev/sda1)."},
        "destination": {"type": "string", "description": "Output image file path."}
    }, "required": ["source", "destination"]}, timeout=3600)

_register("file_recovery", "Recover deleted files from disk image using foremost/scalpel.",
    "forensic", RiskLevel.LOW, False, file_recovery,
    {"type": "object", "properties": {
        "image_path": {"type": "string", "description": "Disk image file path."},
        "output_dir": {"type": "string", "description": "Output directory (default: /tmp/recovered)."}
    }, "required": ["image_path"]}, timeout=300)

_register("memory_dump", "Dump live system memory for forensic analysis.",
    "forensic", RiskLevel.MEDIUM, False, memory_dump,
    {"type": "object", "properties": {
        "output_path": {"type": "string", "description": "Output file path (default: /tmp/memory.raw)."}
    }, "required": []}, timeout=120)

_register("memory_analysis", "Analyze memory dump with Volatility 3. Commands: pslist, pstree, netscan, cmdline, malfind, filescan, hashdump, dlllist.",
    "forensic", RiskLevel.LOW, False, memory_analysis,
    {"type": "object", "properties": {
        "dump_path": {"type": "string", "description": "Memory dump file path."},
        "command": {"type": "string", "enum": ["pslist", "pstree", "netscan", "cmdline", "malfind", "filescan", "hashdump", "dlllist", "handles", "svcscan"], "description": "Analysis command."}
    }, "required": ["dump_path", "command"]}, timeout=120)

_register("metadata_extract", "Extract metadata from files (EXIF, document properties, timestamps).",
    "forensic", RiskLevel.LOW, False, metadata_extract,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "File to analyze."}
    }, "required": ["filepath"]}, timeout=10)

_register("string_extract", "Extract printable strings from binary/file for analysis.",
    "forensic", RiskLevel.LOW, False, string_extract,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "File to extract strings from."},
        "min_length": {"type": "integer", "description": "Minimum string length (default: 6)."}
    }, "required": ["filepath"]}, timeout=15)

_register("binwalk_analysis", "Analyze firmware/binary for embedded files and file systems.",
    "forensic", RiskLevel.LOW, False, binwalk_analysis,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "Binary/firmware file to analyze."}
    }, "required": ["filepath"]}, timeout=30)

_register("log_timeline", "Create unified timeline from multiple log sources (auth, syslog, kern, web).",
    "forensic", RiskLevel.LOW, False, log_timeline,
    {"type": "object", "properties": {
        "hours": {"type": "integer", "description": "Look back N hours (default: 24, max: 168)."}
    }, "required": []}, timeout=30)

_register("browser_forensic", "Extract browser forensic data: history, downloads (Firefox, Chrome).",
    "forensic", RiskLevel.LOW, False, browser_forensic,
    {"type": "object", "properties": {
        "user": {"type": "string", "description": "Username (default: current user)."}
    }, "required": []}, timeout=15)

_register("pcap_analysis", "Analyze PCAP network capture: protocols, conversations, DNS, HTTP requests.",
    "forensic", RiskLevel.LOW, False, pcap_analysis,
    {"type": "object", "properties": {
        "pcap_file": {"type": "string", "description": "PCAP file path."},
        "filter_expr": {"type": "string", "description": "Display filter (e.g., 'ip.addr==1.2.3.4', 'http')."}
    }, "required": ["pcap_file"]}, timeout=30)

_register("evidence_hash", "Calculate MD5/SHA1/SHA256 hashes for evidence chain of custody.",
    "forensic", RiskLevel.LOW, False, evidence_hash,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "Evidence file to hash."}
    }, "required": ["filepath"]}, timeout=30)


# ============================================================
# M22: DFIR (Enhanced)
# ============================================================

from quarr.tools.dfir import (  # noqa: E402 (intentional sectioned import before domain registration)
    build_incident_timeline,
    chain_of_custody,
    evtx_analysis,
    incident_triage,
    malware_analyze,
)

_register("incident_triage", "Automated incident triage: check connections, processes, ports, logins, cron, files, services in one shot.",
    "dfir", RiskLevel.LOW, False, incident_triage,
    {"type": "object", "properties": {}, "required": []}, timeout=60)

_register("evtx_analysis", "Parse Windows Event Log (.evtx) files. Filter by event IDs (4624=login, 4625=failed, 4688=process, 7045=service).",
    "dfir", RiskLevel.LOW, False, evtx_analysis,
    {"type": "object", "properties": {
        "evtx_file": {"type": "string", "description": "Path to .evtx file."},
        "event_ids": {"type": "string", "description": "Comma-separated event IDs to filter (e.g., '4624,4625,4688')."}
    }, "required": ["evtx_file"]}, timeout=30)

_register("malware_analyze", "Basic malware analysis: file type, hashes, entropy, strings (URLs/IPs/commands), PE/ELF info, packer detection.",
    "dfir", RiskLevel.LOW, False, malware_analyze,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "Suspicious file to analyze."}
    }, "required": ["filepath"]}, timeout=30)

_register("build_incident_timeline", "Build comprehensive incident timeline from all log sources + bash history. Sorted chronologically.",
    "dfir", RiskLevel.LOW, False, build_incident_timeline,
    {"type": "object", "properties": {
        "hours": {"type": "integer", "description": "Look back N hours (default: 48, max: 168)."},
        "output_file": {"type": "string", "description": "Save timeline to file (optional)."}
    }, "required": []}, timeout=30)

_register("chain_of_custody", "Manage evidence chain of custody: collect (hash + metadata), verify (integrity check), list entries.",
    "dfir", RiskLevel.LOW, False, chain_of_custody,
    {"type": "object", "properties": {
        "filepath": {"type": "string", "description": "Evidence file path."},
        "action": {"type": "string", "enum": ["collect", "verify", "list"], "description": "Action: collect, verify, or list."},
        "notes": {"type": "string", "description": "Notes about the evidence (optional)."}
    }, "required": ["filepath", "action"]}, timeout=30)


# ============================================================
# M23: THREAT INTELLIGENCE
# ============================================================

from quarr.tools.threat_intel import (  # noqa: E402 (intentional sectioned import before domain registration)
    abuseipdb_check,
    cve_lookup,
    shodan_lookup,
    threat_feed_check,
    virustotal_lookup,
)

_register("virustotal_lookup", "VirusTotal lookup: check file hash, IP, domain, or URL reputation. Requires VIRUSTOTAL_API_KEY.",
    "threat_intel", RiskLevel.LOW, False, virustotal_lookup,
    {"type": "object", "properties": {
        "ioc_type": {"type": "string", "enum": ["hash", "ip", "domain", "url"], "description": "IOC type."},
        "value": {"type": "string", "description": "Hash, IP, domain, or URL to check."}
    }, "required": ["ioc_type", "value"]}, timeout=20)

_register("abuseipdb_check", "Check IP reputation on AbuseIPDB. Requires ABUSEIPDB_API_KEY.",
    "threat_intel", RiskLevel.LOW, False, abuseipdb_check,
    {"type": "object", "properties": {
        "ip_address": {"type": "string", "description": "IP address to check."}
    }, "required": ["ip_address"]}, timeout=15)

_register("cve_lookup", "Lookup CVE from NVD (National Vulnerability Database). Search by CVE ID or keyword.",
    "threat_intel", RiskLevel.LOW, False, cve_lookup,
    {"type": "object", "properties": {
        "cve_id": {"type": "string", "description": "CVE ID (e.g., CVE-2021-44228)."},
        "keyword": {"type": "string", "description": "Keyword search (e.g., 'Apache log4j')."}
    }, "required": []}, timeout=20)

_register("shodan_lookup", "Shodan host intelligence: ports, services, vulnerabilities, organization. Requires SHODAN_API_KEY.",
    "threat_intel", RiskLevel.LOW, False, shodan_lookup,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "IP address or hostname."}
    }, "required": ["target"]}, timeout=15)

_register("threat_feed_check", "Aggregate threat intelligence from all available sources (VT, AbuseIPDB, Shodan, NVD).",
    "threat_intel", RiskLevel.LOW, False, threat_feed_check,
    {"type": "object", "properties": {
        "ioc_type": {"type": "string", "enum": ["hash", "ip", "domain", "url", "cve"], "description": "IOC type."},
        "value": {"type": "string", "description": "IOC value to check."}
    }, "required": ["ioc_type", "value"]}, timeout=30)


# ============================================================
# M24: VULNERABILITY ASSESSMENT (Extended)
# ============================================================

from quarr.tools.vuln_assess import (  # noqa: E402 (intentional sectioned import before domain registration)
    config_audit,
    hardening_check,
    linux_security_audit,
    patch_assessment,
)

_register("linux_security_audit", "CIS Benchmark-based Linux security audit: passwords, SSH, SUID, permissions, kernel, patching.",
    "vuln_assessment", RiskLevel.LOW, False, linux_security_audit,
    {"type": "object", "properties": {}, "required": []}, timeout=30)

_register("patch_assessment", "Check for available security updates and kernel versions.",
    "vuln_assessment", RiskLevel.LOW, False, patch_assessment,
    {"type": "object", "properties": {}, "required": []}, timeout=30)

_register("config_audit", "Security configuration audit for services: SSH, Apache, Nginx, MySQL.",
    "vuln_assessment", RiskLevel.LOW, False, config_audit,
    {"type": "object", "properties": {
        "service": {"type": "string", "enum": ["all", "ssh", "apache", "nginx", "mysql"], "description": "Service to audit (default: all)."}
    }, "required": []}, timeout=15)

_register("hardening_check", "Quick hardening checklist with score: firewall, SSH, ASLR, fail2ban, etc.",
    "vuln_assessment", RiskLevel.LOW, False, hardening_check,
    {"type": "object", "properties": {}, "required": []}, timeout=15)


# ============================================================
# M25: SECURITY OPERATIONS
# ============================================================

from quarr.tools.secops import (  # noqa: E402 (intentional sectioned import before domain registration)
    compliance_report,
    get_playbook,
    list_playbooks,
    security_health_check,
    security_metrics,
)

_register("security_health_check", "Comprehensive security health check with score (0-100). Runs hardening, patches, connections, processes.",
    "secops", RiskLevel.LOW, False, security_health_check,
    {"type": "object", "properties": {}, "required": []}, timeout=60)

_register("list_playbooks", "List available incident response playbooks (brute_force, malware, data_breach, web_attack).",
    "secops", RiskLevel.LOW, False, list_playbooks,
    {"type": "object", "properties": {}, "required": []}, timeout=5)

_register("get_playbook", "Get detailed incident response playbook with steps and recommended actions.",
    "secops", RiskLevel.LOW, False, get_playbook,
    {"type": "object", "properties": {
        "name": {"type": "string", "enum": ["brute_force_response", "malware_response", "data_breach_response", "web_attack_response"], "description": "Playbook name."}
    }, "required": ["name"]}, timeout=5)

_register("security_metrics", "Generate security metrics dashboard: failed logins, connections, listening ports.",
    "secops", RiskLevel.LOW, False, security_metrics,
    {"type": "object", "properties": {}, "required": []}, timeout=30)

_register("compliance_report", "Generate compliance status report. Frameworks: cis (CIS Benchmark), pci (PCI-DSS basic).",
    "secops", RiskLevel.LOW, False, compliance_report,
    {"type": "object", "properties": {
        "framework": {"type": "string", "enum": ["cis", "pci"], "description": "Compliance framework."}
    }, "required": []}, timeout=60)


# ============================================================
# API SECURITY (OWASP API Top 10)
# ============================================================

from quarr.tools.api_security import (  # noqa: E402 (intentional sectioned import before domain registration)
    api_bola_check,
    api_data_exposure_check,
    api_endpoint_discovery,
    jwt_analyze,
)

_register(
    "api_endpoint_discovery",
    "Discover REST API endpoints by locating and parsing an OpenAPI/Swagger spec. Lists every path and method.",
    "recon", RiskLevel.LOW, True, api_endpoint_discovery,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Base API URL, e.g. http://host:port"}
    }, "required": ["target"]}, timeout=30)

_register(
    "api_data_exposure_check",
    "Test a JSON API endpoint for Excessive Data Exposure (OWASP API3): flags sensitive fields (password, token, ssn, ...) in the response.",
    "vuln_scan", RiskLevel.LOW, True, api_data_exposure_check,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Full JSON endpoint URL to fetch."},
        "headers": {"type": "string", "description": "Optional 'Key: Value' header lines separated by ';;' (e.g. an Authorization header)."}
    }, "required": ["target"]}, timeout=30)

_register(
    "api_bola_check",
    "Test Broken Object Level Authorization / BOLA (OWASP API1): using one user's token, attempt to access another user's object.",
    "exploit", RiskLevel.MEDIUM, True, api_bola_check,
    {"type": "object", "properties": {
        "target": {"type": "string", "description": "Base API URL."},
        "object_path": {"type": "string", "description": "Object path with '{id}' placeholder, e.g. /users/v1/{id}"},
        "id_a": {"type": "string", "description": "The authenticated user's own object id."},
        "id_b": {"type": "string", "description": "Another user's object id to attempt to access."},
        "token_a": {"type": "string", "description": "The authenticated user's bearer token (optional)."}
    }, "required": ["target", "object_path", "id_a", "id_b"]}, timeout=30)

_register(
    "jwt_analyze",
    "Analyze a JWT for weaknesses: alg=none, weak/guessable HS256 secret, and decode claims. No network needed.",
    "vuln_scan", RiskLevel.LOW, False, jwt_analyze,
    {"type": "object", "properties": {
        "token": {"type": "string", "description": "The JWT string (header.payload.signature)."}
    }, "required": ["token"]}, timeout=15)


def get_tool(name: str) -> ToolMeta | None:
    return TOOL_REGISTRY.get(name)

def get_available_tools() -> list:
    return list(TOOL_REGISTRY.keys())

def get_tools_for_llm() -> list:
    """Tool definitions for Ollama tool calling API."""
    tools = []
    for _name, meta in TOOL_REGISTRY.items():
        tools.append({
            "type": "function",
            "function": {
                "name": meta.name,
                "description": meta.description,
                "parameters": meta.parameters,
            }
        })
    return tools

def get_tools_summary() -> str:
    """Human-readable tool summary for LLM context."""
    categories = {}
    for name, meta in TOOL_REGISTRY.items():
        cat = meta.category
        if cat not in categories:
            categories[cat] = []
        params = ", ".join(meta.parameters.get("required", []))
        categories[cat].append(
            f"  {name}({params}) - {meta.description} [risk: {meta.risk.value}]"
        )

    lines = ["AVAILABLE TOOLS:"]
    for cat, entries in categories.items():
        lines.append(f"\n  [{cat.upper()}]")
        lines.extend(entries)
    return "\n".join(lines)
