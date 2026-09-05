"""
methodology.py - Pentest methodology playbooks (reference knowledge).

Factual, evidence-based phase -> technique -> tool mappings distilled from the
STRUCTURE and tooling of well-known references:

  - "The Hacker Playbook 3" (THP3) by Peter Kim
  - "Operator Handbook: Red Team + OSINT + Blue Team Reference" by Joshua Picolet
  - "RTFM: Red Team Field Manual v2" by Ben Clark
  - "Bug Bounty Bootcamp" by Vickie Li
  - "Hacking APIs" by Corey J. Ball
  - "The Web Application Hacker's Handbook" by Stuttard & Pinto
  - "The Mobile Application Hacker's Handbook" by Chell, Erasmus, Colley & Whitehouse
  - "Malware Analyst's Cookbook" (Ligh et al.) & "Hacking Exposed: Malware & Rootkits"
  - "Network Forensics: Tracking Hackers Through Cyberspace" (Davidoff & Ham)
  - "Digital Forensics with Open Source Tools" (Altheide & Carvey)
  - OWASP MASTG (Mobile App Security Testing Guide, CC BY-SA)

This module encodes *facts* (which tools/techniques apply to which pentest
phase) and short checklists — NOT the books' prose. Each entry carries a source
attribution. It is injected as RAG context (via quarr/knowledge/base.py) so the
agent recalls a proven methodology at the relevant phase.

The tool lists reflect the tools most emphasized by each reference (measured by
their prominence in the source material) intersected with QUARR's own toolset.
"""

from __future__ import annotations

# Each playbook: phase key -> {name, techniques, tools, checklist, sources}
# `phase` aligns with QuarrAgent._detect_phase(): recon, discovery, vuln_scan,
# exploit. `domains` are finer tags used for keyword matching.
METHODOLOGY_PLAYBOOKS = [
    {
        "phase": "recon",
        "domains": ["recon", "osint", "external"],
        "name": "External Recon & OSINT",
        "techniques": [
            "passive subdomain discovery",
            "service/port discovery",
            "SSL certificate & search-engine enumeration",
            "email/employee OSINT",
        ],
        "tools": ["nmap", "masscan", "amass", "subfinder", "shodan", "recon-ng"],
        "checklist": [
            "Enumerate subdomains passively before active scans.",
            "Diff Nmap results over time to spot new exposed services.",
            "Search service/network engines (Shodan) for exposed assets.",
        ],
        "sources": ["THP3 ch.2 (Red Team Recon)", "Operator Handbook (OSINT)"],
    },
    {
        "phase": "discovery",
        "domains": ["web", "discovery", "content"],
        "name": "Web Application Discovery & Mapping",
        "techniques": [
            "content/endpoint discovery",
            "technology fingerprinting",
            "parameter discovery",
        ],
        "tools": ["gobuster", "ffuf", "burp", "nuclei", "wpscan"],
        "checklist": [
            "Fingerprint the stack before choosing exploits.",
            "Brute-force content and enumerate API endpoints/params.",
            "Map auth flows (register -> login -> token) for API targets.",
        ],
        "sources": ["THP3 ch.3 (Web Application Exploitation)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["web", "vuln_scan", "exploitation"],
        "name": "Web Exploitation",
        "techniques": [
            "sql injection", "xss", "ssrf", "xxe", "deserialization",
            "file inclusion (lfi/rfi)",
        ],
        "tools": ["sqlmap", "burp", "nuclei"],
        "checklist": [
            "Prioritize injection classes (SQLi/XSS/SSRF/XXE) on dynamic params.",
            "Validate a detected issue with a second technique before confirming.",
            "For deserialization, identify the framework first.",
        ],
        "sources": ["THP3 ch.3", "Operator Handbook (Web)"],
    },
    {
        "phase": "exploit",
        "domains": ["network", "lateral", "credentials"],
        "name": "Network Compromise & Lateral Movement",
        "techniques": [
            "credential discovery", "password spraying", "ntlm relay",
            "lateral movement (psexec/wmiexec/rdp)", "pivoting",
        ],
        "tools": ["crackmapexec", "impacket", "psexec", "wmiexec", "responder", "evil-winrm"],
        "checklist": [
            "Enumerate users without credentials first, then spray carefully.",
            "Use Responder/NTLM-relay where SMB signing is disabled.",
            "Move laterally with living-off-the-land + psexec/wmiexec.",
        ],
        "sources": ["THP3 ch.4 (Compromising the Network)", "Operator Handbook (Red Team)"],
    },
    {
        "phase": "exploit",
        "domains": ["ad", "active_directory", "kerberos", "credentials"],
        "name": "Active Directory Attack Chain",
        "techniques": [
            "AS-REP roasting", "kerberoasting", "pass-the-hash", "pass-the-ticket",
            "DCSync", "golden/silver ticket",
        ],
        "tools": ["bloodhound", "impacket", "mimikatz", "secretsdump", "rubeus", "powerview", "crackmapexec"],
        "checklist": [
            "Map attack paths with BloodHound before acting.",
            "Try AS-REP roasting (no-preauth) and Kerberoasting (SPNs) for offline cracking.",
            "With DA/replication rights, DCSync the krbtgt hash.",
        ],
        "sources": ["THP3 ch.4 (Living Off the Land / Dumping DC Hashes)",
                    "Operator Handbook (Active Directory)"],
    },
    {
        "phase": "exploit",
        "domains": ["privesc", "privilege_escalation", "post"],
        "name": "Privilege Escalation",
        "techniques": [
            "local enumeration (Windows/Linux)", "misconfiguration abuse",
            "UAC bypass", "token impersonation",
        ],
        "tools": ["winpeas", "linpeas", "seatbelt", "powerview", "mimikatz"],
        "checklist": [
            "Run automated local enum (winPEAS/linPEAS) first.",
            "Check service/scheduled-task/registry misconfigurations.",
            "On Windows, review token privileges for impersonation paths.",
        ],
        "sources": ["THP3 ch.4 (Privilege Escalation)", "Operator Handbook (Privesc)"],
    },
    {
        "phase": "exploit",
        "domains": ["persistence", "c2", "post"],
        "name": "Persistence & C2",
        "techniques": [
            "command-and-control beaconing", "scheduled-task/service persistence",
            "credential material harvesting",
        ],
        "tools": ["empire", "cobalt strike", "metasploit", "mimikatz"],
        "checklist": [
            "Establish resilient C2 with jitter/redirectors.",
            "Prefer least-noisy persistence appropriate to the objective.",
            "Harvest credentials for follow-on lateral movement.",
        ],
        "sources": ["THP3 ch.1 (Tools of the Trade)", "THP3 ch.6 (Persistence)",
                    "Operator Handbook (C2)"],
    },
    {
        "phase": "recon",
        "domains": ["social", "phishing", "social_engineering"],
        "name": "Social Engineering / Phishing",
        "techniques": ["phishing campaigns", "payload delivery", "credential capture"],
        "tools": ["gophish", "empire", "msfvenom"],
        "checklist": [
            "Build a realistic pretext and infrastructure before sending.",
            "Track click/credential capture; pivot from the first foothold.",
        ],
        "sources": ["THP3 ch.5 (Social Engineering)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["api", "rest", "graphql", "web"],
        "name": "API Security Testing (OWASP API Top 10)",
        "techniques": [
            "bola / idor", "broken authentication", "mass assignment",
            "excessive data exposure", "jwt weaknesses", "graphql abuse",
            "rate-limit / business-logic flaws",
        ],
        "tools": ["burp", "postman", "kiterunner", "arjun", "jwt_tool", "ffuf"],
        "checklist": [
            "Enumerate the API surface (OpenAPI/Swagger, kiterunner, arjun params).",
            "Test object IDs across users for BOLA/IDOR; try mass assignment on writes.",
            "Analyze JWTs (alg=none, weak secret) and check auth on every endpoint.",
        ],
        "sources": ["Hacking APIs (Corey J. Ball)", "Bug Bounty Bootcamp (Vickie Li)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["web", "bugbounty", "appsec"],
        "name": "Web Bug Hunting Methodology",
        "techniques": [
            "xss", "csrf", "ssrf", "xxe", "idor", "deserialization",
            "open redirect", "access control flaws",
        ],
        "tools": ["burp", "ffuf", "wfuzz", "sqlmap", "nuclei"],
        "checklist": [
            "Map every input/parameter and auth boundary first.",
            "Chain lower-severity bugs (open redirect + SSRF, IDOR + info leak).",
            "Verify access-control on each object/function, not just the UI.",
        ],
        "sources": ["Bug Bounty Bootcamp (Vickie Li)",
                    "The Web Application Hacker's Handbook (Stuttard & Pinto)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["mobile", "android", "ios", "apk", "masvs"],
        "name": "Mobile App Security Testing (OWASP MASVS/MASTG)",
        "techniques": [
            "insecure data storage (MASVS-STORAGE)",
            "weak cryptography (MASVS-CRYPTO)",
            "insecure network / cleartext & pinning (MASVS-NETWORK)",
            "platform interaction & exported components (MASVS-PLATFORM)",
            "authentication (MASVS-AUTH)",
            "code quality & resilience (MASVS-CODE / MASVS-RESILIENCE)",
        ],
        "tools": ["apktool", "jadx", "frida", "objection", "adb", "drozer", "mobsf"],
        "checklist": [
            "STORAGE: inspect SharedPrefs/SQLite/external storage for plaintext secrets.",
            "NETWORK: check cleartext traffic + certificate pinning (bypass with Frida).",
            "PLATFORM: review exported activities/services/providers & deeplinks.",
        ],
        "sources": ["OWASP MASTG (Mobile App Security Testing Guide, CC BY-SA)",
                    "The Mobile Application Hacker's Handbook (Chell, Erasmus, Colley, Whitehouse)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["android", "ipc", "mobile", "intent"],
        "name": "Android IPC & Component Attacks",
        "techniques": [
            "exported activity/service/receiver/provider abuse",
            "intent injection & deeplink hijacking",
            "insecure WebView (JS bridge / file access)",
            "content-provider SQL injection & path traversal",
            "clipboard / tapjacking",
        ],
        "tools": ["drozer", "adb", "frida", "objection", "apktool"],
        "checklist": [
            "Enumerate exported components with drozer; probe them for unauthorized access.",
            "Fuzz deeplinks/intents; test WebViews for addJavascriptInterface & file access.",
            "Query content providers for SQLi and traversal on their URIs.",
        ],
        "sources": ["The Mobile Application Hacker's Handbook (Chell et al.)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["ios", "mobile", "jailbreak", "keychain"],
        "name": "iOS App Assessment",
        "techniques": [
            "keychain / data-protection inspection",
            "jailbreak & SSL-pinning detection bypass",
            "runtime manipulation & method hooking",
            "binary analysis (encryption, symbols)",
        ],
        "tools": ["frida", "objection", "cycript", "otool", "class-dump", "hopper"],
        "checklist": [
            "Inspect Keychain + Data Protection classes for sensitive material.",
            "Bypass jailbreak detection & SSL pinning (Frida/objection) to intercept traffic.",
            "Analyze the decrypted binary (otool/class-dump) for logic & secrets.",
        ],
        "sources": ["The Mobile Application Hacker's Handbook (Chell et al.)"],
    },
    {
        "phase": "recon",
        "domains": ["command_reference", "recon", "network"],
        "name": "Operator Command Reference (recon → post-ex)",
        "techniques": [
            "host/service discovery", "credential ops", "quick pivots",
        ],
        "tools": ["nmap", "curl", "sqlmap", "impacket", "mimikatz"],
        "checklist": [
            "Keep a tight recon→enumerate→exploit→post-ex loop.",
            "Prefer concise, repeatable one-liners; log everything for the report.",
        ],
        "sources": ["RTFM: Red Team Field Manual v2 (Ben Clark)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["dfir", "malware", "malware_analysis", "reverse_engineering", "blue"],
        "name": "Malware Analysis (static + dynamic)",
        "techniques": [
            "triage: file type, hashing, entropy/packer detection",
            "static analysis (strings, imports, PE/ELF headers)",
            "dynamic/behavioral analysis (sandbox, API calls)",
            "YARA signature matching & IOC extraction",
            "C2 / persistence identification",
        ],
        "tools": ["yara", "volatility", "strings", "ida", "cuckoo", "pefile"],
        "checklist": [
            "Triage first: hash, file type, entropy (high entropy → packed).",
            "Pull static IOCs (URLs/IPs/mutexes) before detonating.",
            "Detonate in an isolated sandbox; capture API/registry/network behavior.",
            "Write/apply YARA rules to hunt the sample family across the estate.",
        ],
        "sources": ["Malware Analyst's Cookbook (Ligh, Adair, Hartstein, Richard)",
                    "Hacking Exposed: Malware & Rootkits"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["dfir", "network_forensics", "forensic", "blue", "hunting"],
        "name": "Network Forensics & Traffic Analysis",
        "techniques": [
            "full packet capture & pcap analysis",
            "flow analysis (NetFlow) for beaconing/exfil",
            "protocol/IDS log correlation",
            "C2 channel & DNS-tunneling detection",
            "incident timeline reconstruction",
        ],
        "tools": ["wireshark", "tshark", "tcpdump", "snort", "suricata", "zeek", "netflow"],
        "checklist": [
            "Capture at a choke point; carve sessions by conversation.",
            "Hunt beaconing via flow periodicity and long-lived connections.",
            "Correlate IDS (snort/suricata) + Zeek logs to reconstruct the timeline.",
        ],
        "sources": ["Network Forensics: Tracking Hackers Through Cyberspace (Davidoff & Ham)"],
    },
    {
        "phase": "vuln_scan",
        "domains": ["dfir", "forensic", "incident_response", "disk_forensics", "memory", "blue"],
        "name": "Disk/Memory Forensics & Incident Response",
        "techniques": [
            "sound acquisition & chain of custody (imaging, hashing)",
            "memory forensics (processes, injected code, rootkits)",
            "disk analysis & deleted-file carving",
            "Windows registry & artifact timeline",
        ],
        "tools": ["volatility", "sleuthkit", "autopsy", "foremost", "scalpel", "regripper", "strings"],
        "checklist": [
            "Acquire before you analyze: image + hash, preserve chain of custody.",
            "Memory: enumerate processes, detect injection/rootkit hooks (Volatility).",
            "Disk: build a super-timeline; carve deleted files; parse registry hives.",
        ],
        "sources": ["Digital Forensics with Open Source Tools (Altheide & Carvey)",
                    "Computer Forensics: Investigating Network Intrusions and Cyber Crime"],
    },
]

_SOURCE_NOTE = (
    "Methodology references: 'The Hacker Playbook 3' (Peter Kim) and "
    "'Operator Handbook' (Joshua Picolet) — structure/tooling only."
)


def get_methodology(
    phase: str | None = None,
    domains: list[str] | None = None,
    query: str = "",
    max_results: int = 2,
) -> str:
    """Return relevant methodology playbook(s) formatted for LLM context.

    Matches on phase and/or domain/technology/query keywords. Returns "" if
    nothing relevant. Every returned block includes its source attribution.
    """
    phase = (phase or "").strip().lower()
    dom = {d.strip().lower() for d in (domains or []) if d}
    q = (query or "").lower()

    scored = []
    for pb in METHODOLOGY_PLAYBOOKS:
        score = 0
        if phase and pb["phase"] == phase:
            score += 3
        if dom and (dom & set(pb["domains"])):
            score += 4
        # Match domain/technique/name keywords in the free-text query. Normalize
        # underscores<->spaces so a natural-language objective ("privilege
        # escalation") matches a token like "privilege_escalation".
        haystack_terms = pb["domains"] + pb["techniques"] + [pb["name"].lower()]
        for kw in haystack_terms:
            kw_norm = kw.replace("_", " ")
            if kw in q or kw_norm in q:
                score += 2
        if score > 0:
            scored.append((score, pb))

    if not scored:
        return ""
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [pb for _, pb in scored[:max_results]]

    lines = ["METHODOLOGY PLAYBOOK (reference):"]
    for pb in top:
        lines.append(f"  ▸ {pb['name']}  [{pb['phase']}]")
        lines.append(f"    Techniques: {', '.join(pb['techniques'][:5])}")
        lines.append(f"    Tools: {', '.join(pb['tools'][:6])}")
        for step in pb["checklist"][:3]:
            lines.append(f"    - {step}")
        lines.append(f"    Source: {'; '.join(pb['sources'])}")
    return "\n".join(lines)


def list_playbooks() -> list[str]:
    """Names of all methodology playbooks (for tests / introspection)."""
    return [pb["name"] for pb in METHODOLOGY_PLAYBOOKS]
