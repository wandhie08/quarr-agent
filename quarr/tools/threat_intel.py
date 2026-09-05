"""
threat_intel_tools.py - M23: Threat Intelligence

Integrasi threat feed dan IOC enrichment:
- VirusTotal lookup (hash, IP, domain)
- AbuseIPDB check
- CVE lookup (NVD)
- Shodan host info
- OTX (AlienVault) pulse check
- Threat feed aggregator

Menggunakan public APIs (beberapa perlu API key di .env).
"""

import json
import os
import re
import shlex
import subprocess


def _http_get(url: str, headers: dict = None, timeout: int = 15) -> str:
    """HTTP GET using curl."""
    cmd = f"curl -s -m {timeout} {shlex.quote(url)}"
    if headers:
        for k, v in headers.items():
            cmd += f" -H {shlex.quote(f'{k}: {v}')}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout + 5)
        return result.stdout if result.stdout else "[No response]"
    except Exception as e:
        return f"[ERROR] {str(e)}"


# ============================================================
# VirusTotal
# ============================================================

def virustotal_lookup(ioc_type: str, value: str) -> str:
    """
    VirusTotal lookup. ioc_type: hash, ip, domain, url.
    Requires VIRUSTOTAL_API_KEY in .env.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return "[ERROR] VIRUSTOTAL_API_KEY not set in .env. Get free key at https://virustotal.com"

    value = value.strip()
    headers = {"x-apikey": api_key}

    if ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{value}"
    elif ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{value}"
    elif ioc_type == "url":
        import base64
        url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        return "[ERROR] Unknown type. Use: hash, ip, domain, url"

    raw = _http_get(url, headers=headers)

    try:
        data = json.loads(raw)
        attrs = data.get("data", {}).get("attributes", {})

        results = [f"=== VIRUSTOTAL: {ioc_type} = {value} ==="]

        if ioc_type == "hash":
            stats = attrs.get("last_analysis_stats", {})
            results.append(f"Detections: {stats.get('malicious', 0)}/{sum(stats.values())}")
            results.append(f"Type: {attrs.get('type_description', '?')}")
            results.append(f"Name: {attrs.get('meaningful_name', '?')}")
            results.append(f"Size: {attrs.get('size', '?')} bytes")
            tags = attrs.get("tags", [])
            if tags:
                results.append(f"Tags: {', '.join(tags)}")
            if stats.get("malicious", 0) > 0:
                results.append(f"\n🚨 MALICIOUS — {stats['malicious']} engines detected this file")

        elif ioc_type == "ip":
            stats = attrs.get("last_analysis_stats", {})
            results.append(f"Malicious: {stats.get('malicious', 0)}")
            results.append(f"Country: {attrs.get('country', '?')}")
            results.append(f"AS: {attrs.get('as_owner', '?')}")
            results.append(f"Network: {attrs.get('network', '?')}")

        elif ioc_type == "domain":
            stats = attrs.get("last_analysis_stats", {})
            results.append(f"Malicious: {stats.get('malicious', 0)}")
            results.append(f"Registrar: {attrs.get('registrar', '?')}")
            results.append(f"Creation: {attrs.get('creation_date', '?')}")

        return "\n".join(results)

    except json.JSONDecodeError:
        return f"[ERROR] Invalid response: {raw[:200]}"


# ============================================================
# AbuseIPDB
# ============================================================

def abuseipdb_check(ip_address: str) -> str:
    """
    Check IP reputation on AbuseIPDB.
    Requires ABUSEIPDB_API_KEY in .env.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return "[ERROR] ABUSEIPDB_API_KEY not set. Get free key at https://abuseipdb.com"

    ip_address = ip_address.strip()
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90&verbose"
    headers = {"Key": api_key, "Accept": "application/json"}
    raw = _http_get(url, headers=headers)

    try:
        data = json.loads(raw).get("data", {})
        results = [
            f"=== ABUSEIPDB: {ip_address} ===",
            f"Abuse Score: {data.get('abuseConfidenceScore', '?')}%",
            f"Total Reports: {data.get('totalReports', 0)}",
            f"Country: {data.get('countryCode', '?')}",
            f"ISP: {data.get('isp', '?')}",
            f"Domain: {data.get('domain', '?')}",
            f"Usage: {data.get('usageType', '?')}",
            f"Whitelisted: {data.get('isWhitelisted', False)}",
        ]
        score = data.get("abuseConfidenceScore", 0)
        if score > 50:
            results.append(f"\n🚨 HIGH RISK — Abuse score {score}%")
        elif score > 20:
            results.append(f"\n⚠️ MODERATE RISK — Abuse score {score}%")
        else:
            results.append(f"\n✅ LOW RISK — Abuse score {score}%")
        return "\n".join(results)

    except json.JSONDecodeError:
        return f"[ERROR] Invalid response: {raw[:200]}"


# ============================================================
# CVE Lookup (NVD)
# ============================================================

def cve_lookup(cve_id: str = "", keyword: str = "") -> str:
    """
    Lookup CVE dari NVD (National Vulnerability Database).
    Bisa search by CVE ID atau keyword.
    """
    if cve_id:
        cve_id = cve_id.strip().upper()
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    elif keyword:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword.replace(' ', '+')}&resultsPerPage=5"
    else:
        return "[ERROR] Provide cve_id or keyword"

    raw = _http_get(url, timeout=20)

    try:
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"No CVE found for: {cve_id or keyword}"

        results = []
        for vuln in vulns[:5]:
            cve = vuln.get("cve", {})
            cve_id_str = cve.get("id", "?")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

            metrics = cve.get("metrics", {})
            cvss_data = {}
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics:
                    cvss_data = metrics[version][0].get("cvssData", {})
                    break

            results.append(
                f"=== {cve_id_str} ===\n"
                f"Score: {cvss_data.get('baseScore', '?')} ({cvss_data.get('baseSeverity', '?')})\n"
                f"Vector: {cvss_data.get('vectorString', '?')}\n"
                f"Description: {desc[:300]}\n"
            )

        return "\n".join(results)

    except json.JSONDecodeError:
        return f"[ERROR] NVD response error: {raw[:200]}"


# ============================================================
# Shodan
# ============================================================

def shodan_lookup(target: str) -> str:
    """
    Shodan host lookup.
    Requires SHODAN_API_KEY in .env.
    """
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        return "[ERROR] SHODAN_API_KEY not set. Get key at https://shodan.io"

    target = target.strip()
    # Resolve domain to IP if needed
    if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        import socket
        try:
            target = socket.gethostbyname(target)
        except Exception:
            return f"[ERROR] Cannot resolve: {target}"

    url = f"https://api.shodan.io/shodan/host/{target}?key={api_key}"
    raw = _http_get(url)

    try:
        data = json.loads(raw)
        if "error" in data:
            return f"[ERROR] Shodan: {data['error']}"

        results = [
            f"=== SHODAN: {target} ===",
            f"Organization: {data.get('org', '?')}",
            f"ISP: {data.get('isp', '?')}",
            f"Country: {data.get('country_name', '?')}",
            f"OS: {data.get('os', '?')}",
            f"Ports: {data.get('ports', [])}",
            f"Vulns: {data.get('vulns', 'none')}",
        ]

        for svc in data.get("data", [])[:5]:
            results.append(
                f"\n  Port {svc.get('port')}/{svc.get('transport', '?')}: "
                f"{svc.get('product', '?')} {svc.get('version', '')}"
            )

        return "\n".join(results)

    except json.JSONDecodeError:
        return f"[ERROR] Shodan response error: {raw[:200]}"


# ============================================================
# Threat Feed Aggregator (Offline/Free)
# ============================================================

def threat_feed_check(ioc_type: str, value: str) -> str:
    """
    Check IOC against multiple free threat feeds.
    Aggregates results from available sources.
    """
    value = value.strip()
    results = [f"=== THREAT INTEL: {ioc_type} = {value} ===\n"]
    sources_checked = 0

    # 1. VirusTotal (if key available)
    if os.environ.get("VIRUSTOTAL_API_KEY"):
        vt = virustotal_lookup(ioc_type, value)
        if "[ERROR]" not in vt:
            results.append(vt)
            sources_checked += 1

    # 2. AbuseIPDB (if IP + key available)
    if ioc_type == "ip" and os.environ.get("ABUSEIPDB_API_KEY"):
        abuse = abuseipdb_check(value)
        if "[ERROR]" not in abuse:
            results.append(f"\n{abuse}")
            sources_checked += 1

    # 3. Shodan (if IP/domain + key available)
    if ioc_type in ("ip", "domain") and os.environ.get("SHODAN_API_KEY"):
        shodan = shodan_lookup(value)
        if "[ERROR]" not in shodan:
            results.append(f"\n{shodan}")
            sources_checked += 1

    # 4. NVD CVE (if looks like CVE)
    if ioc_type == "cve" or (ioc_type == "hash" and value.upper().startswith("CVE-")):
        cve = cve_lookup(cve_id=value)
        results.append(f"\n{cve}")
        sources_checked += 1

    results.append(f"\n--- Checked {sources_checked} source(s) ---")

    if sources_checked == 0:
        results.append("\n[INFO] No API keys configured. Set in .env:")
        results.append("  VIRUSTOTAL_API_KEY=xxx")
        results.append("  ABUSEIPDB_API_KEY=xxx")
        results.append("  SHODAN_API_KEY=xxx")

    return "\n".join(results)
