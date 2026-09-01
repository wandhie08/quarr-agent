"""
knowledge.py - M5: RAG Knowledge Base

Embedded security knowledge untuk agent reasoning.
Tidak memerlukan vector database — menggunakan keyword-based retrieval
yang context-aware (berdasarkan fase, service, teknologi).

Sources:
- OWASP Web Security Testing Guide (WSTG)
- OWASP API Security Top 10
- OWASP Mobile Top 10
- CWE (Common Weakness Enumeration)
- NIST SP 800-115 (Technical Guide to Information Security Testing)
- MITRE ATT&CK mapping
"""

from typing import List, Dict, Optional


# ============================================================
# OWASP WSTG — Web Security Testing Guide
# ============================================================

OWASP_WSTG = {
    "INFO-01": {
        "id": "WSTG-INFO-01",
        "title": "Conduct Search Engine Discovery Reconnaissance",
        "phase": "recon",
        "description": "Use search engines to find sensitive information about the target (cached pages, exposed documents, error messages, login portals).",
        "tools": ["google dorks", "theHarvester", "subfinder"],
        "cwe": ["CWE-200"],
    },
    "INFO-02": {
        "id": "WSTG-INFO-02",
        "title": "Fingerprint Web Server",
        "phase": "recon",
        "description": "Identify the web server software and version. Different servers have different default configurations and known vulnerabilities.",
        "tools": ["whatweb", "nmap", "web_fingerprint"],
        "cwe": ["CWE-200"],
    },
    "INFO-04": {
        "id": "WSTG-INFO-04",
        "title": "Enumerate Applications on Web Server",
        "phase": "discovery",
        "description": "Discover applications hosted on the web server (virtual hosts, non-standard ports, hidden paths).",
        "tools": ["gobuster", "web_content_discovery", "web_crawl"],
        "cwe": ["CWE-200"],
    },
    "INFO-08": {
        "id": "WSTG-INFO-08",
        "title": "Fingerprint Web Application Framework",
        "phase": "recon",
        "description": "Identify the web application framework to determine known vulnerabilities and attack vectors.",
        "tools": ["whatweb", "web_fingerprint"],
        "cwe": ["CWE-200"],
    },
    "CONF-02": {
        "id": "WSTG-CONF-02",
        "title": "Test Application Platform Configuration",
        "phase": "vuln_scan",
        "description": "Review platform configuration for security issues: default files, directory listing, unnecessary HTTP methods, security headers.",
        "tools": ["nikto", "vulnerability_scan"],
        "cwe": ["CWE-16"],
    },
    "CONF-05": {
        "id": "WSTG-CONF-05",
        "title": "Enumerate Infrastructure and Application Admin Interfaces",
        "phase": "discovery",
        "description": "Find admin interfaces that might be accessible (phpMyAdmin, wp-admin, Tomcat manager, Spring Actuator).",
        "tools": ["gobuster", "web_content_discovery"],
        "cwe": ["CWE-419"],
    },
    "CONF-06": {
        "id": "WSTG-CONF-06",
        "title": "Test HTTP Methods",
        "phase": "vuln_scan",
        "description": "Test for dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT) that could allow data manipulation or XST attacks.",
        "tools": ["nikto", "nmap"],
        "cwe": ["CWE-16"],
    },
    "CONF-07": {
        "id": "WSTG-CONF-07",
        "title": "Test HTTP Strict Transport Security",
        "phase": "vuln_scan",
        "description": "Verify HSTS header is present and properly configured to prevent protocol downgrade attacks.",
        "tools": ["ssl_scan", "vulnerability_scan"],
        "cwe": ["CWE-319"],
    },
    "IDNT-04": {
        "id": "WSTG-IDNT-04",
        "title": "Test Account Enumeration",
        "phase": "exploit",
        "description": "Determine if it is possible to enumerate valid usernames through different error messages or timing differences.",
        "tools": ["bruteforce_login", "web_crawl"],
        "cwe": ["CWE-204"],
    },
    "ATHN-01": {
        "id": "WSTG-ATHN-01",
        "title": "Test Credentials Transported over Encrypted Channel",
        "phase": "vuln_scan",
        "description": "Verify that credentials are always transmitted over encrypted connections (HTTPS).",
        "tools": ["ssl_scan"],
        "cwe": ["CWE-319", "CWE-523"],
    },
    "ATHN-02": {
        "id": "WSTG-ATHN-02",
        "title": "Test for Default Credentials",
        "phase": "exploit",
        "description": "Test for default usernames and passwords on discovered services and applications.",
        "tools": ["bruteforce_login", "vulnerability_scan"],
        "cwe": ["CWE-521"],
    },
    "ATHN-03": {
        "id": "WSTG-ATHN-03",
        "title": "Test for Weak Lock Out Mechanism",
        "phase": "exploit",
        "description": "Determine whether account lockout exists and if it can be bypassed.",
        "tools": ["bruteforce_login"],
        "cwe": ["CWE-307"],
    },
    "INPV-01": {
        "id": "WSTG-INPV-01",
        "title": "Test for Reflected Cross-Site Scripting",
        "phase": "exploit",
        "description": "Test if user input is reflected in the response without proper encoding, allowing XSS execution.",
        "tools": ["xss_scan", "dalfox"],
        "cwe": ["CWE-79"],
    },
    "INPV-02": {
        "id": "WSTG-INPV-02",
        "title": "Test for Stored Cross-Site Scripting",
        "phase": "exploit",
        "description": "Test if user input is stored and rendered without encoding, allowing persistent XSS.",
        "tools": ["xss_scan"],
        "cwe": ["CWE-79"],
    },
    "INPV-05": {
        "id": "WSTG-INPV-05",
        "title": "Test for SQL Injection",
        "phase": "exploit",
        "description": "Test if user input is incorporated into SQL queries without proper parameterization.",
        "tools": ["sqli_scan", "sqlmap"],
        "cwe": ["CWE-89"],
    },
    "INPV-12": {
        "id": "WSTG-INPV-12",
        "title": "Test for Command Injection",
        "phase": "exploit",
        "description": "Test if user input is passed to OS commands without proper sanitization.",
        "tools": ["command_injection_scan", "commix"],
        "cwe": ["CWE-78"],
    },
    "INPV-19": {
        "id": "WSTG-INPV-19",
        "title": "Test for Server-Side Request Forgery (SSRF)",
        "phase": "exploit",
        "description": "Test if the application can be tricked into making requests to internal resources.",
        "tools": ["vulnerability_scan"],
        "cwe": ["CWE-918"],
    },
    "CRYP-01": {
        "id": "WSTG-CRYP-01",
        "title": "Test for Weak Transport Layer Security",
        "phase": "vuln_scan",
        "description": "Assess the SSL/TLS configuration for weak protocols, ciphers, and certificate issues.",
        "tools": ["ssl_scan", "sslscan"],
        "cwe": ["CWE-326", "CWE-327"],
    },
}


# ============================================================
# OWASP API Security Top 10 (2023)
# ============================================================

OWASP_API_TOP10 = {
    "API1": {
        "id": "API1:2023",
        "title": "Broken Object Level Authorization (BOLA)",
        "description": "APIs expose endpoints that handle object identifiers, creating a wide attack surface for Object Level Access Control issues. Authorization checks should be considered in every function that accesses a data source using input from the user.",
        "impact": "Unauthorized access to other users' data. In banking: access to other accounts/transactions.",
        "test": "Change object IDs in API requests (e.g., /api/users/123 → /api/users/124) and check if access is granted.",
        "cwe": ["CWE-284", "CWE-285"],
        "remediation": "Implement proper authorization checks for every object access. Use random/unpredictable IDs.",
    },
    "API2": {
        "id": "API2:2023",
        "title": "Broken Authentication",
        "description": "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws.",
        "impact": "Account takeover, unauthorized access to all user data.",
        "test": "Test weak passwords, missing rate limiting on login, JWT vulnerabilities (none algorithm, weak secret), token expiration.",
        "cwe": ["CWE-287", "CWE-307"],
        "remediation": "Use strong authentication mechanisms, implement rate limiting, validate JWT properly.",
    },
    "API3": {
        "id": "API3:2023",
        "title": "Broken Object Property Level Authorization",
        "description": "Lack of or improper authorization validation at property level. Mass assignment / excessive data exposure.",
        "impact": "Attacker can modify properties they shouldn't (e.g., role, balance) or read sensitive fields.",
        "test": "Add extra fields to requests (mass assignment). Check if responses contain sensitive fields not needed by the client.",
        "cwe": ["CWE-213", "CWE-915"],
        "remediation": "Explicitly define which properties can be read/written per role.",
    },
    "API4": {
        "id": "API4:2023",
        "title": "Unrestricted Resource Consumption",
        "description": "API requests consume resources (network, CPU, memory, storage). No limits = DoS risk.",
        "impact": "Denial of Service, financial damage from excessive API calls.",
        "test": "Test missing rate limiting, large payload handling, pagination limits, file upload size limits.",
        "cwe": ["CWE-770", "CWE-400"],
        "remediation": "Implement rate limiting, pagination limits, payload size limits, timeout.",
    },
    "API5": {
        "id": "API5:2023",
        "title": "Broken Function Level Authorization",
        "description": "Complex access control policies with different hierarchies, groups, roles, and unclear separation between admin and regular functions.",
        "impact": "Regular user can access admin functions.",
        "test": "Access admin endpoints as regular user. Test horizontal and vertical privilege escalation.",
        "cwe": ["CWE-285"],
        "remediation": "Implement consistent authorization module. Deny by default.",
    },
}


# ============================================================
# CWE — Common Weakness Enumeration (key entries)
# ============================================================

CWE_DATABASE = {
    "CWE-79": {
        "id": "CWE-79",
        "name": "Improper Neutralization of Input During Web Page Generation (XSS)",
        "severity": "medium-high",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
        "remediation": "Use context-aware output encoding. Implement Content Security Policy (CSP). Use framework auto-escaping.",
        "cvss_base": 6.1,
    },
    "CWE-89": {
        "id": "CWE-89",
        "name": "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)",
        "severity": "critical",
        "description": "The software constructs SQL statements from user input without proper neutralization, allowing attackers to modify the intended SQL logic.",
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Use ORM properly.",
        "cvss_base": 9.8,
    },
    "CWE-78": {
        "id": "CWE-78",
        "name": "Improper Neutralization of Special Elements used in an OS Command (Command Injection)",
        "severity": "critical",
        "description": "The software constructs OS commands from user input without proper neutralization.",
        "remediation": "Avoid OS commands where possible. Use allowlists for command arguments. Never pass user input directly to shell.",
        "cvss_base": 9.8,
    },
    "CWE-287": {
        "id": "CWE-287",
        "name": "Improper Authentication",
        "severity": "high",
        "description": "The software does not properly verify the identity of a user.",
        "remediation": "Implement strong authentication mechanisms. Use multi-factor authentication. Validate all authentication tokens server-side.",
        "cvss_base": 8.6,
    },
    "CWE-200": {
        "id": "CWE-200",
        "name": "Exposure of Sensitive Information",
        "severity": "medium",
        "description": "The software exposes sensitive information to unauthorized actors.",
        "remediation": "Minimize information in error messages. Remove debug endpoints in production. Implement proper access controls.",
        "cvss_base": 5.3,
    },
    "CWE-284": {
        "id": "CWE-284",
        "name": "Improper Access Control",
        "severity": "high",
        "description": "The software does not restrict access to a resource properly.",
        "remediation": "Implement authorization checks for every resource access. Use role-based access control. Deny by default.",
        "cvss_base": 8.2,
    },
    "CWE-307": {
        "id": "CWE-307",
        "name": "Improper Restriction of Excessive Authentication Attempts",
        "severity": "high",
        "description": "The software does not implement sufficient measures to prevent brute-force attacks.",
        "remediation": "Implement account lockout after N failed attempts. Use CAPTCHA. Implement progressive delays.",
        "cvss_base": 7.5,
    },
    "CWE-326": {
        "id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "severity": "medium",
        "description": "The software uses encryption with insufficient key length or weak algorithm.",
        "remediation": "Use AES-256 for symmetric encryption. Use RSA-2048+ or ECDSA-256+ for asymmetric. Disable TLS 1.0/1.1.",
        "cvss_base": 5.9,
    },
    "CWE-521": {
        "id": "CWE-521",
        "name": "Weak Password Requirements",
        "severity": "medium",
        "description": "The software does not enforce sufficient password complexity requirements.",
        "remediation": "Require minimum 8+ characters. Check against breached password lists. Implement MFA.",
        "cvss_base": 5.3,
    },
    "CWE-918": {
        "id": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "high",
        "description": "The server can be tricked into making HTTP requests to arbitrary destinations.",
        "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted destinations. Block internal network ranges.",
        "cvss_base": 8.6,
    },
}


# ============================================================
# CVSS v3.1 Scoring Reference
# ============================================================

CVSS_REFERENCE = {
    "critical": {"range": "9.0-10.0", "description": "Exploitation requires minimal effort with maximum impact. Immediate patching required."},
    "high": {"range": "7.0-8.9", "description": "Significant impact, relatively easy to exploit. Patch within days."},
    "medium": {"range": "4.0-6.9", "description": "Moderate impact, requires some conditions to exploit. Patch within weeks."},
    "low": {"range": "0.1-3.9", "description": "Minor impact, difficult to exploit. Patch in next release cycle."},
    "info": {"range": "0.0", "description": "Informational finding, no direct security impact."},
}


# ============================================================
# Retriever — Context-Aware Knowledge Retrieval
# ============================================================

def retrieve_knowledge(
    phase: str = None,
    services: List[str] = None,
    technologies: List[str] = None,
    finding_type: str = None,
    query: str = None,
    max_results: int = 5,
) -> str:
    """
    Context-aware knowledge retrieval.

    Tidak hanya vector similarity — mempertimbangkan:
    - Current phase (recon, discovery, vuln_scan, exploit)
    - Discovered services (http, ssh, smb, mysql)
    - Technologies (WordPress, Apache, IIS, PHP, ASP.NET)
    - Finding type (sqli, xss, auth, etc)
    - Free-text query

    Returns: formatted string untuk disisipkan ke LLM context.
    """
    results = []
    services = services or []
    technologies = technologies or []
    query_lower = (query or "").lower()

    # 1. OWASP WSTG berdasarkan phase
    if phase:
        for key, wstg in OWASP_WSTG.items():
            if wstg["phase"] == phase:
                results.append(f"[{wstg['id']}] {wstg['title']}: {wstg['description']}")

    # 2. CWE berdasarkan finding type
    type_cwe_map = {
        "sqli": "CWE-89", "sql_injection": "CWE-89", "sql": "CWE-89",
        "xss": "CWE-79", "cross-site": "CWE-79",
        "command_injection": "CWE-78", "rce": "CWE-78",
        "auth": "CWE-287", "authentication": "CWE-287",
        "idor": "CWE-284", "access_control": "CWE-284", "bola": "CWE-284",
        "ssrf": "CWE-918",
        "brute": "CWE-307", "bruteforce": "CWE-307",
        "ssl": "CWE-326", "tls": "CWE-326", "crypto": "CWE-326",
        "password": "CWE-521",
        "info_disclosure": "CWE-200", "information": "CWE-200",
    }
    if finding_type:
        cwe_id = type_cwe_map.get(finding_type.lower())
        if cwe_id and cwe_id in CWE_DATABASE:
            cwe = CWE_DATABASE[cwe_id]
            results.append(
                f"[{cwe['id']}] {cwe['name']}\n"
                f"  Severity: {cwe['severity']} | CVSS Base: {cwe['cvss_base']}\n"
                f"  {cwe['description']}\n"
                f"  Remediation: {cwe['remediation']}"
            )

    # 3. OWASP API Top 10 jika API-related
    api_keywords = ["api", "rest", "graphql", "endpoint", "json", "jwt"]
    if any(k in query_lower for k in api_keywords) or any("api" in s.lower() for s in services):
        for key, api in OWASP_API_TOP10.items():
            if query_lower and any(w in api["title"].lower() or w in api["description"].lower()
                                   for w in query_lower.split()):
                results.append(f"[{api['id']}] {api['title']}: {api['description']}\n  Test: {api['test']}")

    # 3b. OWASP Mobile Top 10 jika mobile-related
    mobile_keywords = ["mobile", "android", "ios", "apk", "app", "adb", "frida", "objection", "deeplink", "webview"]
    if any(k in query_lower for k in mobile_keywords):
        for key, mob in OWASP_MOBILE_TOP10.items():
            results.append(f"[{mob['id']}] {mob['title']}: {mob['description']}\n  Test: {mob['test']}")
            if len(results) >= max_results:
                break

    # 4. Technology-specific
    tech_lower = [t.lower() for t in technologies]
    if any("wordpress" in t for t in tech_lower):
        results.append("WordPress: Use cms_scan (wpscan) to enumerate plugins, themes, users. Check for XML-RPC, wp-config.php backup, REST API exposure.")
    if any("iis" in t for t in tech_lower):
        results.append("IIS: Check for WebDAV (CVE-2017-7269), short filename disclosure, ASP.NET debugging, trace.axd, elmah.axd.")
    if any("apache" in t for t in tech_lower):
        results.append("Apache: Check for mod_status, mod_info exposure, .htaccess bypass, path traversal (CVE-2021-41773), server-status.")
    if any("spring" in t or "actuator" in t for t in tech_lower):
        results.append("Spring Boot: Check /actuator endpoints (env, heapdump, configprops). These expose sensitive configuration and credentials.")
    if any("php" in t for t in tech_lower):
        results.append("PHP: Test for file inclusion (LFI/RFI), type juggling, deserialization, phpinfo() exposure, debug mode.")

    # 5. Service-specific
    for svc in services:
        svc_lower = svc.lower()
        if "smb" in svc_lower or "445" in svc_lower:
            results.append("SMB: Check null session, anonymous access, writable shares, EternalBlue (MS17-010), signing disabled.")
        if "ssh" in svc_lower or "22" in svc_lower:
            results.append("SSH: Check weak credentials, key-based auth only, version vulnerabilities, allowed algorithms.")
        if "ftp" in svc_lower or "21" in svc_lower:
            results.append("FTP: Check anonymous access, writable directories, bounce attack, cleartext credentials.")
        if "mysql" in svc_lower or "3306" in svc_lower:
            results.append("MySQL: Check default credentials (root:root), remote access enabled, UDF exploitation, file read/write privileges.")
        if "dns" in svc_lower or "53" in svc_lower:
            results.append("DNS: Check zone transfer (AXFR), subdomain enumeration, DNS rebinding, cache poisoning.")

    # 6. Query-based fallback
    if query and not results:
        for key, wstg in OWASP_WSTG.items():
            if any(w in wstg["title"].lower() or w in wstg["description"].lower()
                   for w in query_lower.split()):
                results.append(f"[{wstg['id']}] {wstg['title']}: {wstg['description']}")
        for cwe_id, cwe in CWE_DATABASE.items():
            if any(w in cwe["name"].lower() or w in cwe["description"].lower()
                   for w in query_lower.split()):
                results.append(f"[{cwe['id']}] {cwe['name']}: {cwe['remediation']}")

    # 7. Blue team / Incident Response knowledge
    blue_keywords = ["defense", "defend", "monitor", "incident", "response", "detect", "block",
                     "firewall", "log", "audit", "suspicious", "compromise", "breach", "alert",
                     "blue team", "soc", "siem"]
    if any(k in query_lower for k in blue_keywords):
        for phase, desc in NIST_IR_PHASES.items():
            results.append(f"[NIST IR - {phase.upper()}] {desc}")
            if len(results) >= max_results:
                break

    # 8. Forensic knowledge
    forensic_keywords = ["forensic", "memory", "disk", "timeline", "evidence", "investigate",
                         "artifact", "recover", "volatility", "pcap", "dump", "image"]
    if any(k in query_lower for k in forensic_keywords):
        results.append("[NIST SP 800-86] Digital Forensic: Preserve evidence integrity, maintain chain of custody, document all actions, use write blockers for disk imaging.")
        results.append("[FORENSIC] Order of volatility: CPU registers → RAM → disk cache → disk → remote logs → backups. Collect most volatile first.")
        results.append("[FORENSIC] Memory analysis: Use pslist/pstree for processes, netscan for connections, malfind for injected code, cmdline for command history.")

    # 9. MITRE ATT&CK
    threat_keywords = ["mitre", "attack", "technique", "tactic", "persistence", "lateral",
                       "exfiltration", "c2", "command and control", "credential", "evasion"]
    if any(k in query_lower for k in threat_keywords):
        for tid, tech in MITRE_TECHNIQUES.items():
            if any(w in tech["name"].lower() or w in tech["tactic"].lower() or w in tech["detect"].lower()
                   for w in query_lower.split()):
                results.append(f"[{tid}] {tech['name']} ({tech['tactic']}): {tech['detect']}")

    # Deduplicate and limit
    seen = set()
    unique = []
    for r in results:
        if r not in seen:
            seen.add(r)
            unique.append(r)

    unique = unique[:max_results]

    if not unique:
        return ""

    return "RELEVANT SECURITY KNOWLEDGE:\n" + "\n\n".join(unique)


def get_cwe_for_finding(finding_title: str) -> Optional[Dict]:
    """Get CWE info based on finding title keywords."""
    title_lower = finding_title.lower()
    keyword_map = {
        "sql injection": "CWE-89", "sqli": "CWE-89",
        "xss": "CWE-79", "cross-site scripting": "CWE-79",
        "command injection": "CWE-78",
        "ssrf": "CWE-918",
        "idor": "CWE-284", "broken access": "CWE-284",
        "authentication": "CWE-287", "auth bypass": "CWE-287",
        "brute": "CWE-307",
        "ssl": "CWE-326", "tls": "CWE-326", "weak cipher": "CWE-326",
        "password": "CWE-521", "default credential": "CWE-521",
        "information disclosure": "CWE-200", "info leak": "CWE-200",
    }
    for keyword, cwe_id in keyword_map.items():
        if keyword in title_lower:
            return CWE_DATABASE.get(cwe_id)
    return None



# ============================================================
# OWASP Mobile Top 10 (2024)
# ============================================================

OWASP_MOBILE_TOP10 = {
    "M1": {
        "id": "M1:2024",
        "title": "Improper Credential Usage",
        "description": "Hardcoded credentials, insecure credential storage, or improper use of biometric authentication.",
        "test": "Decompile APK → search for hardcoded API keys, passwords, tokens. Check SharedPreferences for plaintext credentials.",
        "tools": ["apk_secrets_scan", "adb_storage_check"],
    },
    "M2": {
        "id": "M2:2024",
        "title": "Inadequate Supply Chain Security",
        "description": "Vulnerable third-party libraries, SDKs, or components included in the app.",
        "test": "Check build.gradle/pom.xml for outdated dependencies. Scan with dependency-check tools.",
        "tools": ["apk_decompile"],
    },
    "M3": {
        "id": "M3:2024",
        "title": "Insecure Authentication/Authorization",
        "description": "Weak authentication mechanisms, missing session management, broken access control.",
        "test": "Test login bypass, token manipulation, session fixation. Check JWT implementation.",
        "tools": ["bruteforce_login", "sqli_scan"],
    },
    "M4": {
        "id": "M4:2024",
        "title": "Insufficient Input/Output Validation",
        "description": "Missing or improper input validation leading to injection attacks (SQLi, XSS, command injection).",
        "test": "Test API endpoints for injection. Check WebView JavaScript interface exposure.",
        "tools": ["sqli_scan", "xss_scan", "command_injection_scan"],
    },
    "M5": {
        "id": "M5:2024",
        "title": "Insecure Communication",
        "description": "Missing or broken SSL/TLS, no certificate pinning, cleartext traffic allowed.",
        "test": "Check network_security_config.xml. Test certificate pinning bypass. Monitor traffic for cleartext.",
        "tools": ["apk_network_config", "frida_ssl_bypass", "ssl_scan"],
    },
    "M6": {
        "id": "M6:2024",
        "title": "Inadequate Privacy Controls",
        "description": "Excessive data collection, PII leakage via logs/storage/network.",
        "test": "Check logcat for PII. Check storage for sensitive data. Review permissions in manifest.",
        "tools": ["adb_logcat_check", "adb_storage_check", "apk_manifest_analysis"],
    },
    "M7": {
        "id": "M7:2024",
        "title": "Insufficient Binary Protections",
        "description": "No code obfuscation, no root/jailbreak detection, no anti-tampering.",
        "test": "Decompile APK — is code readable? Check for root detection. Check for integrity verification.",
        "tools": ["apk_decompile", "objection_explore"],
    },
    "M8": {
        "id": "M8:2024",
        "title": "Security Misconfiguration",
        "description": "Debug mode enabled, allowBackup, exported components without protection, weak signing.",
        "test": "Analyze AndroidManifest.xml for misconfigurations. Check APK signing certificate.",
        "tools": ["apk_manifest_analysis", "apk_cert_check"],
    },
    "M9": {
        "id": "M9:2024",
        "title": "Insecure Data Storage",
        "description": "Sensitive data stored in plaintext: SharedPreferences, SQLite, external storage, logs.",
        "test": "Check all storage locations for plaintext secrets. Monitor logcat for data leakage.",
        "tools": ["adb_storage_check", "adb_logcat_check", "apk_secrets_scan"],
    },
    "M10": {
        "id": "M10:2024",
        "title": "Insufficient Cryptography",
        "description": "Weak algorithms (MD5, SHA1, DES), hardcoded keys, improper key management.",
        "test": "Search source for weak crypto usage. Check key storage implementation.",
        "tools": ["apk_secrets_scan", "apk_decompile"],
    },
}


# ============================================================
# NIST Incident Response (SP 800-61) — M19/M20
# ============================================================

NIST_IR_PHASES = {
    "preparation": "Establish incident response capability: policies, tools, communication plans, team training.",
    "detection": "Detect incidents through monitoring, log analysis, IDS/IPS, anomaly detection. Look for: unusual connections, failed logins, new processes, file changes.",
    "analysis": "Determine scope and impact: which systems affected, what data compromised, attack timeline, attacker techniques (MITRE ATT&CK mapping).",
    "containment": "Short-term: isolate affected systems, block attacker IPs. Long-term: patch vulnerabilities, change credentials, rebuild compromised systems.",
    "eradication": "Remove attacker presence: malware, backdoors, unauthorized accounts, persistence mechanisms (cron, services, registry).",
    "recovery": "Restore systems from clean backups, verify integrity, monitor for re-infection, gradually return to production.",
    "lessons_learned": "Document incident timeline, what worked/failed, improve detection and response procedures.",
}

# ============================================================
# MITRE ATT&CK Techniques — M20
# ============================================================

MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "detect": "Monitor process creation, command-line arguments. Check for: powershell -enc, bash -i, python -c."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence", "detect": "Audit cron jobs, at jobs, systemd timers. Use cron_audit tool."},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence", "detect": "Monitor login events, impossible travel, unusual hours. Check auth.log."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "detect": "Failed login attempts in auth.log. Use: log_analysis(auth, filter='Failed')."},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "detect": "DNS tunneling (long queries, TXT records), ICMP data. Use dns_anomaly_check."},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "detect": "Unusual HTTP/HTTPS traffic, beaconing patterns. Analyze with pcap_analysis."},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "detect": "Check systemd services, rc.local, init.d. Use service_audit."},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "detect": "Log gaps, cleared history, timestomped files. Check log_timeline and file_integrity_check."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "detect": "Access to /etc/shadow, SAM hive, lsass.exe. Memory analysis with malfind."},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control", "detect": "New executables in /tmp, /dev/shm, /var/tmp. Use suspicious_files."},
}

def get_cvss_range(severity: str) -> str:
    """Get CVSS score range for a severity level."""
    ref = CVSS_REFERENCE.get(severity.lower(), {})
    return f"CVSS {ref.get('range', 'N/A')}: {ref.get('description', '')}"
