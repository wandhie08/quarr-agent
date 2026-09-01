# API Reference — QUARR Agent (92 Tools)

Complete reference for all 92 tools available in QUARR Agent.

---

## Table of Contents

1. [Tool Structure](#1-tool-structure)
2. [Red Team — Reconnaissance (6)](#2-red-team--reconnaissance-6)
3. [Red Team — Discovery (3)](#3-red-team--discovery-3)
4. [Red Team — Vulnerability Scanning (4)](#4-red-team--vulnerability-scanning-4)
5. [Red Team — Exploitation (5)](#5-red-team--exploitation-5)
6. [Red Team — Network Enumeration (3)](#6-red-team--network-enumeration-3)
7. [Red Team — Mobile Static (5)](#7-red-team--mobile-static-5)
8. [Red Team — Mobile Dynamic (6)](#8-red-team--mobile-dynamic-6)
9. [Red Team — Active Directory Attack (7)](#9-red-team--active-directory-attack-7)
10. [Red Team — Active Directory Enumeration (4)](#10-red-team--active-directory-enumeration-4)
11. [Blue Team — Defense & Monitoring (11)](#11-blue-team--defense--monitoring-11)
12. [Blue Team — Threat Hunting (8)](#12-blue-team--threat-hunting-8)
13. [Forensic — Digital Investigation (11)](#13-forensic--digital-investigation-11)
14. [Threat Intelligence (5)](#14-threat-intelligence-5)
15. [Vulnerability Assessment (4)](#15-vulnerability-assessment-4)
16. [SecOps (5)](#16-secops-5)

---

## 1. Tool Structure

Each tool follows this structure:

```python
{
    "name": "tool_name",
    "description": "What the tool does",
    "parameters": {
        "param1": {"type": "string", "required": True, "description": "..."},
        "param2": {"type": "integer", "required": False, "default": 10}
    },
    "kali_tool": "underlying_command",
    "risk_level": "low|medium|high|critical",
    "category": "recon|discovery|vuln_scan|exploit|..."
}
```

---

## 2. Red Team — Reconnaissance (6)

### target_scope_check

Check target connectivity and basic info.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | IP address or hostname |

```python
# Example
target_scope_check(target="192.168.1.1")

# Returns
{
    "reachable": True,
    "ip": "192.168.1.1",
    "hostname": "server.local",
    "latency_ms": 15
}
```

---

### network_discovery

Discover live hosts in a network range.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | CIDR range (e.g., 192.168.1.0/24) |

```python
# Example
network_discovery(target="192.168.1.0/24")

# Returns
{
    "hosts": [
        {"ip": "192.168.1.1", "status": "up", "mac": "00:11:22:33:44:55"},
        {"ip": "192.168.1.10", "status": "up", "mac": "AA:BB:CC:DD:EE:FF"}
    ],
    "total_up": 2
}
```

---

### service_enumeration

Enumerate services and versions on target.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | IP or hostname |
| `profile` | string | ❌ | "basic" | Scan profile: basic, full, stealth, aggressive |
| `ports` | string | ❌ | "common" | Port specification: common, all, or custom (e.g., "80,443,8080") |

```python
# Example
service_enumeration(target="192.168.1.1", profile="full", ports="1-1000")

# Returns
{
    "host": "192.168.1.1",
    "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.4"},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache/2.4.51"},
        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx/1.21"}
    ]
}
```

---

### subdomain_enum

Enumerate subdomains for a domain.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Root domain (e.g., example.com) |

```python
# Example
subdomain_enum(target="example.com")

# Returns
{
    "domain": "example.com",
    "subdomains": [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
        "admin.example.com"
    ],
    "total": 4
}
```

---

### web_fingerprint

Identify web technologies and CMS.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL or domain |

```python
# Example
web_fingerprint(target="https://example.com")

# Returns
{
    "url": "https://example.com",
    "technologies": [
        {"name": "nginx", "version": "1.21", "category": "Web Server"},
        {"name": "PHP", "version": "8.1", "category": "Programming Language"},
        {"name": "WordPress", "version": "6.0", "category": "CMS"}
    ],
    "headers": {
        "Server": "nginx/1.21",
        "X-Powered-By": "PHP/8.1"
    }
}
```

---

### waf_detection

Detect Web Application Firewall.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL or domain |

```python
# Example
waf_detection(target="https://example.com")

# Returns
{
    "url": "https://example.com",
    "waf_detected": True,
    "waf_name": "Cloudflare",
    "confidence": "high"
}
```

---

## 3. Red Team — Discovery (3)

### web_content_discovery

Brute-force directories and files.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Base URL |
| `wordlist` | string | ❌ | "common" | Wordlist: common, large, api, or custom path |
| `extensions` | string | ❌ | "" | File extensions (e.g., "php,html,js") |

```python
# Example
web_content_discovery(target="https://example.com", wordlist="common", extensions="php,html")

# Returns
{
    "url": "https://example.com",
    "found": [
        {"path": "/admin", "status": 200, "size": 4523},
        {"path": "/backup", "status": 403, "size": 287},
        {"path": "/api", "status": 301, "redirect": "/api/v1"}
    ]
}
```

---

### web_crawl

Crawl website for endpoints and links.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Starting URL |
| `depth` | integer | ❌ | 2 | Crawl depth |

```python
# Example
web_crawl(target="https://example.com", depth=3)

# Returns
{
    "url": "https://example.com",
    "endpoints": [
        "/login",
        "/api/users",
        "/api/products?id=1",
        "/dashboard"
    ],
    "forms": [
        {"action": "/login", "method": "POST", "fields": ["username", "password"]}
    ],
    "js_files": [
        "/static/app.js",
        "/static/api-client.js"
    ]
}
```

---

### parameter_discovery

Discover hidden GET/POST parameters.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL to test |

```python
# Example
parameter_discovery(target="https://example.com/search")

# Returns
{
    "url": "https://example.com/search",
    "parameters": [
        {"name": "q", "type": "GET", "reflected": True},
        {"name": "page", "type": "GET", "reflected": False},
        {"name": "debug", "type": "GET", "reflected": True}
    ]
}
```

---

## 4. Red Team — Vulnerability Scanning (4)

### vulnerability_scan

Scan for CVEs and misconfigurations using Nuclei.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL or IP |
| `severity` | string | ❌ | "critical,high,medium" | Severity filter |
| `tags` | string | ❌ | "" | Template tags (e.g., "cve,misconfig") |

```python
# Example
vulnerability_scan(target="https://example.com", severity="critical,high")

# Returns
{
    "target": "https://example.com",
    "vulnerabilities": [
        {
            "template": "CVE-2021-44228",
            "name": "Log4j RCE",
            "severity": "critical",
            "matched_at": "https://example.com/api",
            "description": "Remote code execution via Log4j"
        }
    ]
}
```

---

### web_vuln_scan

Web server vulnerability scan using Nikto.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL |

```python
# Example
web_vuln_scan(target="https://example.com")

# Returns
{
    "target": "https://example.com",
    "findings": [
        {"id": "OSVDB-3092", "description": "/.git/HEAD accessible", "severity": "medium"},
        {"id": "OSVDB-3233", "description": "Default Apache page", "severity": "info"}
    ]
}
```

---

### ssl_scan

SSL/TLS configuration audit.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Hostname:port |

```python
# Example
ssl_scan(target="example.com:443")

# Returns
{
    "target": "example.com:443",
    "certificate": {
        "subject": "CN=example.com",
        "issuer": "Let's Encrypt",
        "valid_from": "2024-01-01",
        "valid_to": "2024-04-01",
        "days_remaining": 45
    },
    "protocols": {
        "TLSv1.0": "disabled",
        "TLSv1.1": "disabled",
        "TLSv1.2": "enabled",
        "TLSv1.3": "enabled"
    },
    "vulnerabilities": [
        {"name": "BEAST", "status": "not vulnerable"},
        {"name": "POODLE", "status": "not vulnerable"}
    ]
}
```

---

### cms_scan

WordPress/CMS vulnerability scan.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | WordPress URL |
| `enumerate` | string | ❌ | "vp,vt,u" | Enumerate: vp (plugins), vt (themes), u (users) |

```python
# Example
cms_scan(target="https://blog.example.com", enumerate="vp,vt,u")

# Returns
{
    "target": "https://blog.example.com",
    "wordpress_version": "6.0",
    "theme": {"name": "flavor", "version": "1.2"},
    "plugins": [
        {"name": "contact-form-7", "version": "5.5", "vulnerabilities": []},
        {"name": "elementor", "version": "3.5", "vulnerabilities": ["CVE-2022-1234"]}
    ],
    "users": ["admin", "editor", "john"]
}
```

---

## 5. Red Team — Exploitation (5)

### sqli_scan

SQL injection testing using sqlmap.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL with parameter |
| `data` | string | ❌ | "" | POST data |
| `level` | integer | ❌ | 1 | Test level (1-5) |
| `risk` | integer | ❌ | 1 | Risk level (1-3) |

```python
# Example
sqli_scan(target="https://example.com/page?id=1", level=2, risk=2)

# Returns
{
    "target": "https://example.com/page?id=1",
    "vulnerable": True,
    "parameter": "id",
    "injection_type": "UNION-based",
    "dbms": "MySQL",
    "payload": "1' UNION SELECT NULL,@@version--"
}
```

---

### xss_scan

Cross-site scripting testing using Dalfox.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL with parameter |

```python
# Example
xss_scan(target="https://example.com/search?q=test")

# Returns
{
    "target": "https://example.com/search?q=test",
    "vulnerable": True,
    "parameter": "q",
    "xss_type": "Reflected",
    "payload": "<script>alert(1)</script>",
    "poc_url": "https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
}
```

---

### command_injection_scan

OS command injection testing using Commix.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | URL with parameter |
| `data` | string | ❌ | "" | POST data |

```python
# Example
command_injection_scan(target="https://example.com/ping?host=127.0.0.1")

# Returns
{
    "target": "https://example.com/ping?host=127.0.0.1",
    "vulnerable": True,
    "parameter": "host",
    "technique": "classic",
    "payload": "127.0.0.1; id"
}
```

---

### bruteforce_login

Brute-force login credentials using Hydra.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Target (IP or URL) |
| `service` | string | ✅ | - | Service: ssh, ftp, http-post-form, mysql, etc. |
| `username` | string | ❌ | "" | Single username or file path |
| `userlist` | string | ❌ | "" | Username wordlist |
| `password` | string | ❌ | "" | Single password or file path |
| `passlist` | string | ❌ | "" | Password wordlist |

```python
# Example
bruteforce_login(
    target="192.168.1.1",
    service="ssh",
    username="admin",
    passlist="/usr/share/wordlists/rockyou.txt"
)

# Returns
{
    "target": "192.168.1.1",
    "service": "ssh",
    "success": True,
    "credentials": [
        {"username": "admin", "password": "admin123"}
    ]
}
```

---

### exploit_search

Search for exploits using searchsploit.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `query` | string | ✅ | - | Search query (service name, CVE, etc.) |

```python
# Example
exploit_search(query="Apache 2.4.49")

# Returns
{
    "query": "Apache 2.4.49",
    "exploits": [
        {
            "id": "50383",
            "title": "Apache HTTP Server 2.4.49 - Path Traversal",
            "path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.sh",
            "type": "webapps"
        }
    ]
}
```

---

## 6. Red Team — Network Enumeration (3)

### smb_enum

SMB share and user enumeration.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | IP address |

```python
# Example
smb_enum(target="192.168.1.1")

# Returns
{
    "target": "192.168.1.1",
    "shares": [
        {"name": "ADMIN$", "type": "Disk", "access": "NO ACCESS"},
        {"name": "C$", "type": "Disk", "access": "NO ACCESS"},
        {"name": "Public", "type": "Disk", "access": "READ"}
    ],
    "users": ["Administrator", "Guest", "john"],
    "os": "Windows Server 2019"
}
```

---

### dns_enum

DNS records enumeration.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Domain name |

```python
# Example
dns_enum(target="example.com")

# Returns
{
    "domain": "example.com",
    "records": {
        "A": ["93.184.216.34"],
        "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
        "MX": ["mail.example.com"],
        "NS": ["ns1.example.com", "ns2.example.com"],
        "TXT": ["v=spf1 include:_spf.example.com ~all"]
    },
    "zone_transfer": "failed"
}
```

---

### snmp_enum

SNMP enumeration.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | IP address |
| `community` | string | ❌ | "public" | Community string |

```python
# Example
snmp_enum(target="192.168.1.1", community="public")

# Returns
{
    "target": "192.168.1.1",
    "system": {
        "description": "Linux server 5.4.0",
        "contact": "admin@example.com",
        "hostname": "server01"
    },
    "interfaces": [
        {"name": "eth0", "ip": "192.168.1.1", "mac": "00:11:22:33:44:55"}
    ],
    "processes": ["sshd", "apache2", "mysql"]
}
```

---

## 7. Red Team — Mobile Static (5)

### apk_decompile

Decompile APK file.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `apk_path` | string | ✅ | - | Path to APK file |

```python
# Example
apk_decompile(apk_path="/tmp/app.apk")

# Returns
{
    "apk": "/tmp/app.apk",
    "output_dir": "/tmp/quarr_apk",
    "apktool_dir": "/tmp/quarr_apk/apktool",
    "jadx_dir": "/tmp/quarr_apk/jadx",
    "files_count": 450
}
```

---

### apk_secrets_scan

Scan for hardcoded secrets in APK.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `directory` | string | ✅ | - | Decompiled APK directory |

```python
# Example
apk_secrets_scan(directory="/tmp/quarr_apk/jadx")

# Returns
{
    "secrets": [
        {"type": "API_KEY", "value": "sk-live-xxx...", "file": "BuildConfig.java", "line": 15},
        {"type": "FIREBASE", "value": "AIzaSy...", "file": "google-services.json", "line": 3},
        {"type": "AWS_KEY", "value": "AKIA...", "file": "Constants.java", "line": 22}
    ],
    "endpoints": [
        "https://api.example.com/v1",
        "https://api.example.com/auth"
    ]
}
```

---

### apk_manifest_analysis

Analyze AndroidManifest.xml.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `apk_decoded_dir` | string | ✅ | - | apktool output directory |

```python
# Example
apk_manifest_analysis(apk_decoded_dir="/tmp/quarr_apk/apktool")

# Returns
{
    "package": "com.example.app",
    "version": "1.2.3",
    "min_sdk": 21,
    "target_sdk": 33,
    "debuggable": True,
    "allow_backup": True,
    "permissions": ["INTERNET", "CAMERA", "READ_CONTACTS"],
    "exported_components": {
        "activities": ["MainActivity", "DeepLinkActivity"],
        "services": ["BackgroundService"],
        "receivers": ["BootReceiver"]
    },
    "deeplinks": ["myapp://", "https://example.com/app"]
}
```

---

### apk_network_config

Analyze network security configuration.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `apk_decoded_dir` | string | ✅ | - | apktool output directory |

```python
# Example
apk_network_config(apk_decoded_dir="/tmp/quarr_apk/apktool")

# Returns
{
    "cleartext_allowed": True,
    "certificate_pinning": False,
    "trust_anchors": ["system", "user"],
    "domain_config": [
        {"domain": "api.example.com", "cleartext": False, "pinning": False}
    ]
}
```

---

### apk_cert_check

Check APK signing certificate.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `apk_path` | string | ✅ | - | Path to APK file |

```python
# Example
apk_cert_check(apk_path="/tmp/app.apk")

# Returns
{
    "apk": "/tmp/app.apk",
    "signed": True,
    "debug_cert": True,
    "signing_schemes": ["v1", "v2"],
    "certificate": {
        "subject": "CN=Android Debug",
        "issuer": "CN=Android Debug",
        "algorithm": "SHA256withRSA",
        "valid_from": "2024-01-01",
        "valid_to": "2054-01-01"
    }
}
```

---

## 8. Red Team — Mobile Dynamic (6)

### adb_device_check

Check connected Android devices.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
adb_device_check()

# Returns
{
    "devices": [
        {"id": "emulator-5554", "status": "device", "model": "Pixel_4_API_30"},
        {"id": "RF8M33XXXXX", "status": "device", "model": "SM-G973F"}
    ]
}
```

---

### adb_app_info

Get detailed app information.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `package` | string | ✅ | - | Package name |

```python
# Example
adb_app_info(package="com.example.banking")

# Returns
{
    "package": "com.example.banking",
    "version": "3.2.1",
    "version_code": 321,
    "target_sdk": 33,
    "data_dir": "/data/data/com.example.banking",
    "apk_path": "/data/app/com.example.banking/base.apk",
    "permissions": ["INTERNET", "CAMERA", "BIOMETRIC"],
    "first_install": "2024-01-15",
    "last_update": "2024-02-01"
}
```

---

### adb_storage_check

Check insecure data storage.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `package` | string | ✅ | - | Package name |

```python
# Example
adb_storage_check(package="com.example.banking")

# Returns
{
    "package": "com.example.banking",
    "shared_preferences": [
        {"file": "user_prefs.xml", "sensitive_keys": ["auth_token", "user_pin"]}
    ],
    "databases": [
        {"name": "app.db", "tables": ["users", "transactions"], "encrypted": False}
    ],
    "external_storage": [
        "/sdcard/Android/data/com.example.banking/cache/profile.jpg"
    ]
}
```

---

### adb_logcat_check

Check for sensitive data in logs.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `package` | string | ✅ | - | Package name |

```python
# Example
adb_logcat_check(package="com.example.banking")

# Returns
{
    "package": "com.example.banking",
    "sensitive_logs": [
        {"tag": "AuthManager", "message": "Token: eyJhbGci...", "level": "DEBUG"},
        {"tag": "LoginActivity", "message": "Password: user123", "level": "VERBOSE"}
    ]
}
```

---

### frida_ssl_bypass

Bypass SSL certificate pinning.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `package` | string | ✅ | - | Package name |

```python
# Example
frida_ssl_bypass(package="com.example.banking")

# Returns
{
    "package": "com.example.banking",
    "status": "success",
    "bypassed_methods": [
        "TrustManagerImpl.checkServerTrusted",
        "OkHttpClient.Builder.sslSocketFactory"
    ],
    "message": "SSL pinning bypassed. Traffic can now be intercepted."
}
```

---

### objection_explore

Mobile app exploration with Objection.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `package` | string | ✅ | - | Package name |
| `command` | string | ✅ | - | Objection command |

```python
# Example
objection_explore(package="com.example.banking", command="env")

# Returns
{
    "package": "com.example.banking",
    "command": "env",
    "output": {
        "cacheDirectory": "/data/user/0/com.example.banking/cache",
        "codeCacheDirectory": "/data/user/0/com.example.banking/code_cache",
        "externalCacheDirectory": "/storage/emulated/0/Android/data/com.example.banking/cache",
        "filesDirectory": "/data/user/0/com.example.banking/files"
    }
}
```

---

## 9. Red Team — Active Directory Attack (7)

### kerberos_asrep_roast

AS-REP Roasting attack.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | string | ✅ | - | Domain name |
| `dc_ip` | string | ✅ | - | Domain Controller IP |
| `userlist` | string | ❌ | "" | Username list file |

```python
# Example
kerberos_asrep_roast(domain="corp.local", dc_ip="10.10.10.10")

# Returns
{
    "domain": "corp.local",
    "vulnerable_users": [
        {"user": "svc_backup", "hash": "$krb5asrep$23$svc_backup@CORP.LOCAL:..."}
    ],
    "output_file": "/tmp/asrep_hashes.txt"
}
```

---

### kerberos_kerberoast

Kerberoasting attack.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | string | ✅ | - | Domain name |
| `dc_ip` | string | ✅ | - | Domain Controller IP |
| `username` | string | ✅ | - | Valid domain username |
| `password` | string | ✅ | - | User password |

```python
# Example
kerberos_kerberoast(domain="corp.local", dc_ip="10.10.10.10", username="john", password="Pass123")

# Returns
{
    "domain": "corp.local",
    "spn_accounts": [
        {"user": "svc_sql", "spn": "MSSQLSvc/db01.corp.local", "hash": "$krb5tgs$23$*..."}
    ],
    "output_file": "/tmp/kerberoast_hashes.txt"
}
```

---

### secrets_dump

Dump SAM/NTDS secrets.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Target IP |
| `username` | string | ✅ | - | Admin username |
| `password` | string | ✅ | - | Password |
| `domain` | string | ❌ | "" | Domain name |

```python
# Example
secrets_dump(target="10.10.10.10", username="Administrator", password="AdminPass", domain="corp.local")

# Returns
{
    "target": "10.10.10.10",
    "sam_hashes": [
        {"user": "Administrator", "ntlm": "aad3b435b51404eeaad3b435b51404ee:..."}
    ],
    "domain_hashes": [
        {"user": "krbtgt", "ntlm": "..."}
    ],
    "output_file": "/tmp/secrets_dump.txt"
}
```

---

### psexec

Remote command execution via SMB.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Target IP |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |
| `domain` | string | ❌ | "" | Domain name |
| `command` | string | ❌ | "cmd.exe" | Command to execute |

```python
# Example
psexec(target="10.10.10.10", username="admin", password="Pass123", command="whoami")

# Returns
{
    "target": "10.10.10.10",
    "status": "success",
    "output": "corp\\admin"
}
```

---

### wmiexec

Remote command execution via WMI.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Target IP |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |
| `domain` | string | ❌ | "" | Domain name |
| `command` | string | ✅ | - | Command to execute |

```python
# Example
wmiexec(target="10.10.10.10", username="admin", password="Pass123", command="ipconfig")

# Returns
{
    "target": "10.10.10.10",
    "status": "success",
    "output": "Windows IP Configuration..."
}
```

---

### password_spray

Password spraying attack.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Target IP or domain |
| `userlist` | string | ✅ | - | Username list file |
| `password` | string | ✅ | - | Password to spray |
| `protocol` | string | ❌ | "smb" | Protocol: smb, ldap, winrm |

```python
# Example
password_spray(target="10.10.10.10", userlist="/tmp/users.txt", password="Summer2024!")

# Returns
{
    "target": "10.10.10.10",
    "valid_credentials": [
        {"username": "john.doe", "password": "Summer2024!"},
        {"username": "jane.smith", "password": "Summer2024!"}
    ]
}
```

---

### hash_crack

Crack password hashes.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `hash_file` | string | ✅ | - | Path to hash file |
| `mode` | integer | ✅ | - | Hashcat mode (e.g., 1000=NTLM, 13100=Kerberoast) |
| `wordlist` | string | ❌ | "/usr/share/wordlists/rockyou.txt" | Wordlist path |

```python
# Example
hash_crack(hash_file="/tmp/hashes.txt", mode=13100)

# Returns
{
    "hash_file": "/tmp/hashes.txt",
    "mode": 13100,
    "cracked": [
        {"hash": "$krb5tgs$23$*svc_sql...", "password": "Summer2024!"}
    ],
    "total_cracked": 1,
    "total_hashes": 5
}
```

---

## 10. Red Team — Active Directory Enumeration (4)

### ldap_search

LDAP query for users and groups.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | DC IP or domain |
| `domain` | string | ✅ | - | Domain name |
| `username` | string | ❌ | "" | Username (empty for anonymous) |
| `password` | string | ❌ | "" | Password |
| `query` | string | ❌ | "users" | Query type: users, groups, computers, all |

```python
# Example
ldap_search(target="10.10.10.10", domain="corp.local", username="john", password="Pass123", query="users")

# Returns
{
    "domain": "corp.local",
    "users": [
        {"cn": "John Doe", "sAMAccountName": "john.doe", "memberOf": ["Domain Users", "IT"]},
        {"cn": "Admin", "sAMAccountName": "Administrator", "memberOf": ["Domain Admins"]}
    ]
}
```

---

### ldap_domain_dump

Full domain information dump.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | DC IP |
| `domain` | string | ✅ | - | Domain name |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |

```python
# Example
ldap_domain_dump(target="10.10.10.10", domain="corp.local", username="john", password="Pass123")

# Returns
{
    "domain": "corp.local",
    "output_dir": "/tmp/ldapdomaindump",
    "files": [
        "domain_users.json",
        "domain_groups.json",
        "domain_computers.json",
        "domain_policy.json"
    ]
}
```

---

### bloodhound_collect

Collect BloodHound data.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | string | ✅ | - | Domain name |
| `dc_ip` | string | ✅ | - | DC IP |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |
| `collection` | string | ❌ | "Default" | Collection method: Default, All, Session, ACL |

```python
# Example
bloodhound_collect(domain="corp.local", dc_ip="10.10.10.10", username="john", password="Pass123")

# Returns
{
    "domain": "corp.local",
    "output_dir": "/tmp/bloodhound",
    "files": [
        "20240301_computers.json",
        "20240301_users.json",
        "20240301_groups.json",
        "20240301_domains.json"
    ]
}
```

---

### rpc_enum

RPC enumeration (null session).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | Target IP |

```python
# Example
rpc_enum(target="10.10.10.10")

# Returns
{
    "target": "10.10.10.10",
    "null_session": True,
    "domain_info": {
        "domain": "CORP",
        "domain_sid": "S-1-5-21-..."
    },
    "users": ["Administrator", "Guest", "john.doe"],
    "groups": ["Domain Admins", "Domain Users"]
}
```

---

## 11. Blue Team — Defense & Monitoring (11)

### firewall_status

Check firewall rules.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
firewall_status()

# Returns
{
    "iptables": {
        "INPUT": [
            {"target": "ACCEPT", "protocol": "tcp", "source": "0.0.0.0/0", "dport": "22"},
            {"target": "DROP", "protocol": "all", "source": "0.0.0.0/0"}
        ],
        "OUTPUT": [...],
        "FORWARD": [...]
    },
    "ufw": {
        "status": "active",
        "rules": [
            {"to": "22/tcp", "action": "ALLOW", "from": "Anywhere"}
        ]
    }
}
```

---

### firewall_block

Block IP address in firewall.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ip_address` | string | ✅ | - | IP to block |

```python
# Example
firewall_block(ip_address="185.220.101.34")

# Returns
{
    "ip": "185.220.101.34",
    "status": "blocked",
    "rule": "iptables -A INPUT -s 185.220.101.34 -j DROP"
}
```

---

### firewall_unblock

Unblock IP address.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ip_address` | string | ✅ | - | IP to unblock |

```python
# Example
firewall_unblock(ip_address="185.220.101.34")

# Returns
{
    "ip": "185.220.101.34",
    "status": "unblocked"
}
```

---

### log_analysis

Analyze system logs.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `log_type` | string | ✅ | - | Log type: auth, syslog, kern, ufw, fail2ban, apache, nginx |
| `filter_pattern` | string | ❌ | "" | Grep pattern to filter |
| `lines` | integer | ❌ | 100 | Number of lines |

```python
# Example
log_analysis(log_type="auth", filter_pattern="Failed", lines=50)

# Returns
{
    "log_file": "/var/log/auth.log",
    "matches": [
        {"timestamp": "Aug 30 02:15:33", "message": "Failed password for root from 185.220.101.34"},
        {"timestamp": "Aug 30 02:15:34", "message": "Failed password for root from 185.220.101.34"}
    ],
    "total_matches": 47,
    "unique_ips": ["185.220.101.34", "45.33.32.156"]
}
```

---

### active_connections

Check active network connections.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filter_type` | string | ❌ | "all" | Filter: all, established, listening, suspicious |

```python
# Example
active_connections(filter_type="suspicious")

# Returns
{
    "connections": [
        {
            "protocol": "tcp",
            "local": "192.168.1.10:45678",
            "remote": "185.220.101.34:4444",
            "state": "ESTABLISHED",
            "process": "nc",
            "pid": 12345,
            "suspicious_reason": "Known malicious IP, unusual port"
        }
    ]
}
```

---

### port_audit

Audit listening ports.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
port_audit()

# Returns
{
    "listening_ports": [
        {"port": 22, "protocol": "tcp", "process": "sshd", "pid": 1234, "status": "normal"},
        {"port": 80, "protocol": "tcp", "process": "apache2", "pid": 2345, "status": "normal"},
        {"port": 4444, "protocol": "tcp", "process": "nc", "pid": 9999, "status": "suspicious"}
    ],
    "suspicious_count": 1
}
```

---

### process_monitor

Monitor running processes.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
process_monitor()

# Returns
{
    "processes": [
        {"pid": 1234, "user": "root", "cpu": 0.1, "mem": 0.5, "command": "sshd", "status": "normal"},
        {"pid": 9999, "user": "www-data", "cpu": 50.0, "mem": 2.0, "command": "xmrig", "status": "suspicious"}
    ],
    "suspicious": [
        {"pid": 9999, "reason": "Known cryptominer process name"}
    ]
}
```

---

### service_audit

Audit systemd services.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
service_audit()

# Returns
{
    "running_services": [
        {"name": "sshd", "status": "running", "enabled": True},
        {"name": "apache2", "status": "running", "enabled": True}
    ],
    "enabled_services": [...],
    "suspicious_services": [
        {"name": "backdoor.service", "reason": "Unknown service, recently created"}
    ]
}
```

---

### user_audit

Audit user accounts and logins.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
user_audit()

# Returns
{
    "users": [
        {"username": "root", "uid": 0, "shell": "/bin/bash", "last_login": "Aug 30 10:00"},
        {"username": "www-data", "uid": 33, "shell": "/usr/sbin/nologin", "last_login": "Never"}
    ],
    "current_sessions": [
        {"user": "admin", "tty": "pts/0", "from": "192.168.1.100", "login_time": "Aug 30 09:00"}
    ],
    "failed_logins": [
        {"user": "root", "from": "185.220.101.34", "count": 47, "last_attempt": "Aug 30 02:15"}
    ],
    "sudo_users": ["admin", "john"]
}
```

---

### cron_audit

Audit cron jobs.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
cron_audit()

# Returns
{
    "system_cron": [
        {"schedule": "0 * * * *", "command": "/usr/bin/logrotate", "status": "normal"}
    ],
    "user_cron": [
        {"user": "root", "schedule": "*/5 * * * *", "command": "/tmp/.hidden/update.sh", "status": "suspicious"}
    ],
    "suspicious": [
        {"type": "user_cron", "reason": "Hidden directory, frequent execution"}
    ]
}
```

---

### file_integrity_check

Check file integrity and SUID binaries.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `directory` | string | ❌ | "/usr/bin" | Directory to check |
| `days` | integer | ❌ | 7 | Check files modified in last N days |

```python
# Example
file_integrity_check(directory="/usr/bin", days=3)

# Returns
{
    "directory": "/usr/bin",
    "modified_files": [
        {"path": "/usr/bin/sudo", "mtime": "Aug 29 15:00", "size": 232416}
    ],
    "suid_binaries": [
        {"path": "/usr/bin/sudo", "owner": "root", "permissions": "-rwsr-xr-x", "status": "normal"},
        {"path": "/usr/bin/backdoor", "owner": "root", "permissions": "-rwsr-xr-x", "status": "suspicious"}
    ],
    "suspicious": [
        {"path": "/usr/bin/backdoor", "reason": "Unknown SUID binary"}
    ]
}
```

---

## 12. Blue Team — Threat Hunting (8)

### ioc_search

Search for Indicators of Compromise.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ioc_type` | string | ✅ | - | Type: ip, domain, hash, filename, string |
| `value` | string | ✅ | - | IOC value to search |

```python
# Example
ioc_search(ioc_type="ip", value="185.220.101.34")

# Returns
{
    "ioc_type": "ip",
    "value": "185.220.101.34",
    "found_in": [
        {"source": "/var/log/auth.log", "matches": 47, "context": "Failed password attempts"},
        {"source": "ss -an", "matches": 1, "context": "ESTABLISHED connection to :4444"}
    ]
}
```

---

### suspicious_files

Search for suspicious files.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `directory` | string | ❌ | "/tmp" | Directory to search |
| `days` | integer | ❌ | 7 | Files created in last N days |

```python
# Example
suspicious_files(directory="/tmp", days=3)

# Returns
{
    "directory": "/tmp",
    "suspicious": [
        {"path": "/tmp/.x11-unix-hidden", "type": "hidden", "size": 4096, "mtime": "Aug 30 02:00"},
        {"path": "/tmp/shell.elf", "type": "executable", "size": 15234, "mtime": "Aug 30 02:15"}
    ]
}
```

---

### rootkit_scan

Scan for rootkits.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

```python
# Example
rootkit_scan()

# Returns
{
    "chkrootkit": {
        "status": "completed",
        "findings": [
            {"check": "Suckit", "result": "INFECTED"}
        ]
    },
    "rkhunter": {
        "status": "completed",
        "warnings": [
            {"file": "/usr/bin/dir", "reason": "File properties have changed"}
        ]
    }
}
```

---

### yara_scan

Scan with YARA rules.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `directory` | string | ✅ | - | Directory to scan |
| `rules_path` | string | ❌ | "default" | Path to YARA rules |

```python
# Example
yara_scan(directory="/tmp")

# Returns
{
    "directory": "/tmp",
    "matches": [
        {"rule": "Mimikatz", "file": "/tmp/m.exe", "strings": ["sekurlsa", "logonpasswords"]},
        {"rule": "CobaltStrike", "file": "/tmp/beacon.dll", "strings": ["beacon"]}
    ]
}
```

---

### network_capture

Capture network packets.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `interface` | string | ❌ | "eth0" | Network interface |
| `duration` | integer | ❌ | 60 | Capture duration (seconds) |
| `filter` | string | ❌ | "" | BPF filter |
| `output` | string | ❌ | "/tmp/capture.pcap" | Output file |

```python
# Example
network_capture(interface="eth0", duration=30, filter="port 443")

# Returns
{
    "interface": "eth0",
    "duration": 30,
    "packets_captured": 1523,
    "output_file": "/tmp/capture.pcap"
}
```

---

### dns_anomaly_check

Check for DNS anomalies (tunneling, DGA).

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `interface` | string | ❌ | "eth0" | Network interface |
| `duration` | integer | ❌ | 60 | Capture duration |

```python
# Example
dns_anomaly_check(interface="eth0", duration=30)

# Returns
{
    "anomalies": [
        {"type": "long_domain", "domain": "aGVsbG8gd29ybGQ.evil-dns.com", "reason": "Possible DNS tunneling"},
        {"type": "dga", "domain": "asdfjkl123.com", "reason": "Random-looking domain"}
    ],
    "dns_queries": 234,
    "unique_domains": 45
}
```

---

### hash_verify

Calculate file hash.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filepath` | string | ✅ | - | File path |

```python
# Example
hash_verify(filepath="/tmp/suspicious.exe")

# Returns
{
    "file": "/tmp/suspicious.exe",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
}
```

---

### baseline_compare

Compare current state with baseline.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `directory` | string | ✅ | - | Directory to check |

```python
# Example
baseline_compare(directory="/usr/bin")

# Returns
{
    "directory": "/usr/bin",
    "baseline_exists": True,
    "changes": {
        "modified": [
            {"file": "/usr/bin/sudo", "old_hash": "abc...", "new_hash": "def..."}
        ],
        "added": [
            {"file": "/usr/bin/backdoor", "hash": "xyz..."}
        ],
        "deleted": []
    }
}
```

---

## 13. Forensic — Digital Investigation (11)

### disk_image

Create forensic disk image.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `source` | string | ✅ | - | Source device (e.g., /dev/sda1) |
| `destination` | string | ✅ | - | Output file path |

```python
# Example
disk_image(source="/dev/sda1", destination="/evidence/disk.raw")

# Returns
{
    "source": "/dev/sda1",
    "destination": "/evidence/disk.raw",
    "size": "50 GB",
    "hash": {
        "md5": "abc...",
        "sha256": "def..."
    },
    "status": "completed"
}
```

---

### file_recovery

Recover deleted files.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image_path` | string | ✅ | - | Disk image path |
| `output_dir` | string | ❌ | "/tmp/recovered" | Output directory |

```python
# Example
file_recovery(image_path="/evidence/disk.raw")

# Returns
{
    "image": "/evidence/disk.raw",
    "output_dir": "/tmp/recovered",
    "recovered_files": {
        "jpg": 15,
        "pdf": 8,
        "doc": 3,
        "txt": 12
    },
    "total": 38
}
```

---

### memory_dump

Dump live memory.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `output_path` | string | ✅ | - | Output file path |

```python
# Example
memory_dump(output_path="/evidence/memory.raw")

# Returns
{
    "output": "/evidence/memory.raw",
    "size": "16 GB",
    "hash": {
        "sha256": "abc..."
    },
    "status": "completed"
}
```

---

### memory_analysis

Analyze memory dump with Volatility.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `dump_path` | string | ✅ | - | Memory dump path |
| `command` | string | ✅ | - | Volatility command: pslist, netscan, malfind, dlllist, cmdline, filescan |

```python
# Example
memory_analysis(dump_path="/evidence/memory.raw", command="pslist")

# Returns
{
    "dump": "/evidence/memory.raw",
    "command": "pslist",
    "output": [
        {"pid": 4, "name": "System", "ppid": 0, "threads": 150},
        {"pid": 1234, "name": "nc.exe", "ppid": 5678, "threads": 1}
    ]
}
```

---

### metadata_extract

Extract file metadata.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filepath` | string | ✅ | - | File path |

```python
# Example
metadata_extract(filepath="/evidence/document.pdf")

# Returns
{
    "file": "/evidence/document.pdf",
    "metadata": {
        "FileType": "PDF",
        "Creator": "Microsoft Word",
        "Author": "John Doe",
        "CreateDate": "2024-01-15 10:30:00",
        "ModifyDate": "2024-02-20 15:45:00",
        "Producer": "Microsoft: Print To PDF"
    }
}
```

---

### string_extract

Extract strings from binary.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filepath` | string | ✅ | - | File path |
| `min_length` | integer | ❌ | 4 | Minimum string length |

```python
# Example
string_extract(filepath="/evidence/malware.exe")

# Returns
{
    "file": "/evidence/malware.exe",
    "strings": [
        "http://evil-c2.com/gate.php",
        "cmd.exe /c whoami",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "total": 1523,
    "interesting": 15
}
```

---

### binwalk_analysis

Analyze firmware/embedded files.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filepath` | string | ✅ | - | File path |

```python
# Example
binwalk_analysis(filepath="/evidence/firmware.bin")

# Returns
{
    "file": "/evidence/firmware.bin",
    "components": [
        {"offset": 0, "type": "LZMA compressed data"},
        {"offset": 65536, "type": "Squashfs filesystem"},
        {"offset": 1048576, "type": "Linux kernel ARM boot image"}
    ],
    "extracted_dir": "/evidence/firmware.bin.extracted"
}
```

---

### log_timeline

Create unified timeline from logs.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `hours` | integer | ❌ | 24 | Hours to look back |

```python
# Example
log_timeline(hours=48)

# Returns
{
    "timeframe": "48 hours",
    "events": [
        {"timestamp": "2024-08-30 02:15:00", "source": "auth", "event": "Failed password for root from 185.220.101.34"},
        {"timestamp": "2024-08-30 02:15:30", "source": "auth", "event": "Accepted password for www-data from 185.220.101.34"},
        {"timestamp": "2024-08-30 02:16:00", "source": "syslog", "event": "Started session for www-data"},
        {"timestamp": "2024-08-30 02:17:00", "source": "apache", "event": "POST /shell.php 200"}
    ],
    "total_events": 1523
}
```

---

### browser_forensic

Extract browser history.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `user` | string | ✅ | - | Username |

```python
# Example
browser_forensic(user="victim")

# Returns
{
    "user": "victim",
    "firefox": {
        "history": [
            {"url": "http://evil-site.com/exploit.html", "title": "Exploit", "visit_time": "2024-08-30 02:10:00"}
        ],
        "downloads": [
            {"url": "http://evil-site.com/payload.exe", "path": "/home/victim/Downloads/payload.exe"}
        ]
    },
    "chrome": {
        "history": [...],
        "downloads": [...]
    }
}
```

---

### pcap_analysis

Analyze network capture.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `pcap_file` | string | ✅ | - | PCAP file path |
| `filter_expr` | string | ❌ | "" | Wireshark display filter |

```python
# Example
pcap_analysis(pcap_file="/evidence/capture.pcap")

# Returns
{
    "file": "/evidence/capture.pcap",
    "statistics": {
        "packets": 15234,
        "bytes": 10485760,
        "duration": "300 seconds"
    },
    "protocols": {
        "TCP": 85,
        "UDP": 10,
        "ICMP": 5
    },
    "top_conversations": [
        {"src": "192.168.1.10", "dst": "185.220.101.34", "bytes": 5242880, "packets": 3456}
    ],
    "dns_queries": [
        {"query": "evil-c2.com", "count": 47}
    ],
    "http_requests": [
        {"method": "POST", "url": "/gate.php", "host": "evil-c2.com"}
    ]
}
```

---

### evidence_hash

Hash evidence for chain of custody.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `filepath` | string | ✅ | - | Evidence file path |

```python
# Example
evidence_hash(filepath="/evidence/malware.exe")

# Returns
{
    "file": "/evidence/malware.exe",
    "size": 15234,
    "hashes": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    "file_type": "PE32 executable (GUI) Intel 80386",
    "timestamp": "2024-08-30T08:30:00Z"
}
```

---

## 14. Threat Intelligence (5)

### virustotal_lookup

Check file/URL/IP on VirusTotal.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ioc_type` | string | ✅ | - | Type: hash, url, ip, domain |
| `value` | string | ✅ | - | Value to lookup |

---

### abuseipdb_check

Check IP reputation on AbuseIPDB.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ip` | string | ✅ | - | IP address |

---

### shodan_lookup

Search Shodan for host info.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | ✅ | - | IP or search query |

---

### nvd_cve_lookup

Lookup CVE details from NVD.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `cve_id` | string | ✅ | - | CVE ID (e.g., CVE-2021-44228) |

---

### threat_feed_check

Check against threat intelligence feeds.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ioc` | string | ✅ | - | IOC value |
| `ioc_type` | string | ✅ | - | Type: ip, domain, hash |

---

## 15. Vulnerability Assessment (4)

### cis_benchmark

Run CIS Benchmark audit.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `profile` | string | ❌ | "level1" | Profile: level1, level2 |

---

### hardening_check

Check system hardening.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

---

### patch_audit

Audit system patches.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

---

### config_audit

Audit configuration files.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `service` | string | ✅ | - | Service: ssh, apache, nginx, mysql |

---

## 16. SecOps (5)

### security_health_check

Overall security health assessment.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

---

### playbook_execute

Execute IR playbook.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `playbook` | string | ✅ | - | Playbook: brute_force, malware, data_breach, web_attack |

---

### metrics_collect

Collect security metrics.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| - | - | - | - | No parameters |

---

### compliance_check

Check compliance posture.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `framework` | string | ✅ | - | Framework: pci-dss, hipaa, nist, iso27001 |

---

### alert_triage

Triage security alert.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `alert_type` | string | ✅ | - | Alert type |
| `details` | string | ✅ | - | Alert details |
