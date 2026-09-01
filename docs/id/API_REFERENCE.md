# Referensi API — QUARR Agent (92 Tools)

Referensi lengkap untuk semua 92 tools yang tersedia di QUARR Agent.

---

## Daftar Isi

1. [Struktur Tool](#1-struktur-tool)
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

## 1. Struktur Tool

Setiap tool mengikuti struktur ini:

```python
{
    "name": "nama_tool",
    "description": "Fungsi tool",
    "parameters": {
        "param1": {"type": "string", "required": True, "description": "..."},
        "param2": {"type": "integer", "required": False, "default": 10}
    },
    "kali_tool": "command_yang_digunakan",
    "risk_level": "low|medium|high|critical",
    "category": "recon|discovery|vuln_scan|exploit|..."
}
```

---

## 2. Red Team — Reconnaissance (6)

### target_scope_check

Cek konektivitas dan info dasar target.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Alamat IP atau hostname |

```python
# Contoh
target_scope_check(target="192.168.1.1")

# Return
{
    "reachable": True,
    "ip": "192.168.1.1",
    "hostname": "server.local",
    "latency_ms": 15
}
```

---

### network_discovery

Discover host yang aktif dalam range jaringan.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Range CIDR (contoh: 192.168.1.0/24) |

```python
# Contoh
network_discovery(target="192.168.1.0/24")

# Return
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

Enumerasi service dan versi pada target.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | IP atau hostname |
| `profile` | string | ❌ | "basic" | Profil scan: basic, full, stealth, aggressive |
| `ports` | string | ❌ | "common" | Spesifikasi port: common, all, atau custom (contoh: "80,443,8080") |

```python
# Contoh
service_enumeration(target="192.168.1.1", profile="full", ports="1-1000")

# Return
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

Enumerasi subdomain untuk sebuah domain.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Root domain (contoh: example.com) |

```python
# Contoh
subdomain_enum(target="example.com")

# Return
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

Identifikasi teknologi web dan CMS.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL atau domain |

```python
# Contoh
web_fingerprint(target="https://example.com")

# Return
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

Deteksi Web Application Firewall.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL atau domain |

```python
# Contoh
waf_detection(target="https://example.com")

# Return
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

Brute-force direktori dan file.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Base URL |
| `wordlist` | string | ❌ | "common" | Wordlist: common, large, api, atau path custom |
| `extensions` | string | ❌ | "" | Ekstensi file (contoh: "php,html,js") |

```python
# Contoh
web_content_discovery(target="https://example.com", wordlist="common", extensions="php,html")

# Return
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

Crawl website untuk endpoint dan link.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL awal |
| `depth` | integer | ❌ | 2 | Kedalaman crawl |

```python
# Contoh
web_crawl(target="https://example.com", depth=3)

# Return
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

Temukan parameter GET/POST tersembunyi.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL untuk ditest |

```python
# Contoh
parameter_discovery(target="https://example.com/search")

# Return
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

Scan CVE dan misconfig menggunakan Nuclei.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL atau IP |
| `severity` | string | ❌ | "critical,high,medium" | Filter severity |
| `tags` | string | ❌ | "" | Template tags (contoh: "cve,misconfig") |

---

### web_vuln_scan

Web server vulnerability scan menggunakan Nikto.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL |

---

### ssl_scan

Audit konfigurasi SSL/TLS.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Hostname:port |

---

### cms_scan

WordPress/CMS vulnerability scan.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | WordPress URL |
| `enumerate` | string | ❌ | "vp,vt,u" | Enumerate: vp (plugins), vt (themes), u (users) |

---

## 5. Red Team — Exploitation (5)

### sqli_scan

SQL injection testing menggunakan sqlmap.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL dengan parameter |
| `data` | string | ❌ | "" | POST data |
| `level` | integer | ❌ | 1 | Level test (1-5) |
| `risk` | integer | ❌ | 1 | Level risk (1-3) |

---

### xss_scan

Cross-site scripting testing menggunakan Dalfox.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL dengan parameter |

---

### command_injection_scan

OS command injection testing menggunakan Commix.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | URL dengan parameter |
| `data` | string | ❌ | "" | POST data |

---

### bruteforce_login

Brute-force login menggunakan Hydra.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Target (IP atau URL) |
| `service` | string | ✅ | - | Service: ssh, ftp, http-post-form, mysql, dll |
| `username` | string | ❌ | "" | Single username atau path file |
| `userlist` | string | ❌ | "" | Username wordlist |
| `password` | string | ❌ | "" | Single password atau path file |
| `passlist` | string | ❌ | "" | Password wordlist |

---

### exploit_search

Cari exploit menggunakan searchsploit.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `query` | string | ✅ | - | Search query (nama service, CVE, dll) |

---

## 6. Red Team — Network Enumeration (3)

### smb_enum

Enumerasi SMB share dan user.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Alamat IP |

---

### dns_enum

Enumerasi DNS records.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Nama domain |

---

### snmp_enum

Enumerasi SNMP.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Alamat IP |
| `community` | string | ❌ | "public" | Community string |

---

## 7. Red Team — Mobile Static (5)

### apk_decompile

Decompile file APK.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `apk_path` | string | ✅ | - | Path ke file APK |

---

### apk_secrets_scan

Scan hardcoded secrets dalam APK.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `directory` | string | ✅ | - | Direktori APK yang sudah di-decompile |

---

### apk_manifest_analysis

Analisis AndroidManifest.xml.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `apk_decoded_dir` | string | ✅ | - | Direktori output apktool |

---

### apk_network_config

Analisis konfigurasi network security.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `apk_decoded_dir` | string | ✅ | - | Direktori output apktool |

---

### apk_cert_check

Cek sertifikat signing APK.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `apk_path` | string | ✅ | - | Path ke file APK |

---

## 8. Red Team — Mobile Dynamic (6)

### adb_device_check

Cek device Android yang terhubung.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| - | - | - | - | Tidak ada parameter |

---

### adb_app_info

Dapatkan info lengkap aplikasi.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `package` | string | ✅ | - | Nama package |

---

### adb_storage_check

Cek penyimpanan data yang tidak aman.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `package` | string | ✅ | - | Nama package |

---

### adb_logcat_check

Cek data sensitif di logs.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `package` | string | ✅ | - | Nama package |

---

### frida_ssl_bypass

Bypass SSL certificate pinning.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `package` | string | ✅ | - | Nama package |

---

### objection_explore

Mobile app exploration dengan Objection.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `package` | string | ✅ | - | Nama package |
| `command` | string | ✅ | - | Objection command |

---

## 9. Red Team — Active Directory Attack (7)

### kerberos_asrep_roast

AS-REP Roasting attack.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `domain` | string | ✅ | - | Nama domain |
| `dc_ip` | string | ✅ | - | IP Domain Controller |
| `userlist` | string | ❌ | "" | File daftar username |

---

### kerberos_kerberoast

Kerberoasting attack.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `domain` | string | ✅ | - | Nama domain |
| `dc_ip` | string | ✅ | - | IP Domain Controller |
| `username` | string | ✅ | - | Username domain valid |
| `password` | string | ✅ | - | Password user |

---

### secrets_dump

Dump SAM/NTDS secrets.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Target IP |
| `username` | string | ✅ | - | Admin username |
| `password` | string | ✅ | - | Password |
| `domain` | string | ❌ | "" | Nama domain |

---

### psexec

Remote command execution via SMB.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Target IP |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |
| `domain` | string | ❌ | "" | Nama domain |
| `command` | string | ❌ | "cmd.exe" | Command untuk dieksekusi |

---

### wmiexec

Remote command execution via WMI.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Target IP |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |
| `domain` | string | ❌ | "" | Nama domain |
| `command` | string | ✅ | - | Command untuk dieksekusi |

---

### password_spray

Password spraying attack.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Target IP atau domain |
| `userlist` | string | ✅ | - | File daftar username |
| `password` | string | ✅ | - | Password untuk spray |
| `protocol` | string | ❌ | "smb" | Protocol: smb, ldap, winrm |

---

### hash_crack

Crack password hash.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `hash_file` | string | ✅ | - | Path ke file hash |
| `mode` | integer | ✅ | - | Mode Hashcat (contoh: 1000=NTLM, 13100=Kerberoast) |
| `wordlist` | string | ❌ | "/usr/share/wordlists/rockyou.txt" | Path wordlist |

---

## 10. Red Team — Active Directory Enumeration (4)

### ldap_search

LDAP query untuk users dan groups.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | DC IP atau domain |
| `domain` | string | ✅ | - | Nama domain |
| `username` | string | ❌ | "" | Username (kosong untuk anonymous) |
| `password` | string | ❌ | "" | Password |
| `query` | string | ❌ | "users" | Tipe query: users, groups, computers, all |

---

### ldap_domain_dump

Full domain information dump.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | DC IP |
| `domain` | string | ✅ | - | Nama domain |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |

---

### bloodhound_collect

Collect data BloodHound.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `domain` | string | ✅ | - | Nama domain |
| `dc_ip` | string | ✅ | - | DC IP |
| `username` | string | ✅ | - | Username |
| `password` | string | ✅ | - | Password |
| `collection` | string | ❌ | "Default" | Collection method: Default, All, Session, ACL |

---

### rpc_enum

RPC enumeration (null session).

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | Target IP |

---

## 11. Blue Team — Defense & Monitoring (11)

### firewall_status

Cek aturan firewall.

### firewall_block

Block alamat IP di firewall.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `ip_address` | string | ✅ | - | IP untuk diblock |

### firewall_unblock

Unblock alamat IP.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `ip_address` | string | ✅ | - | IP untuk di-unblock |

### log_analysis

Analisis system logs.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `log_type` | string | ✅ | - | Tipe log: auth, syslog, kern, ufw, fail2ban, apache, nginx |
| `filter_pattern` | string | ❌ | "" | Grep pattern untuk filter |
| `lines` | integer | ❌ | 100 | Jumlah baris |

### active_connections

Cek koneksi jaringan aktif.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `filter_type` | string | ❌ | "all" | Filter: all, established, listening, suspicious |

### port_audit

Audit port yang listening.

### process_monitor

Monitor proses yang berjalan.

### service_audit

Audit systemd services.

### user_audit

Audit user accounts dan logins.

### cron_audit

Audit cron jobs.

### file_integrity_check

Cek integritas file dan SUID binaries.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `directory` | string | ❌ | "/usr/bin" | Direktori untuk dicek |
| `days` | integer | ❌ | 7 | Cek file dimodifikasi dalam N hari terakhir |

---

## 12. Blue Team — Threat Hunting (8)

### ioc_search

Cari Indicators of Compromise.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `ioc_type` | string | ✅ | - | Tipe: ip, domain, hash, filename, string |
| `value` | string | ✅ | - | Nilai IOC untuk dicari |

### suspicious_files

Cari file mencurigakan.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `directory` | string | ❌ | "/tmp" | Direktori untuk dicari |
| `days` | integer | ❌ | 7 | File dibuat dalam N hari terakhir |

### rootkit_scan

Scan rootkit.

### yara_scan

Scan dengan YARA rules.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `directory` | string | ✅ | - | Direktori untuk discan |
| `rules_path` | string | ❌ | "default" | Path ke YARA rules |

### network_capture

Capture network packets.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `interface` | string | ❌ | "eth0" | Network interface |
| `duration` | integer | ❌ | 60 | Durasi capture (detik) |
| `filter` | string | ❌ | "" | BPF filter |
| `output` | string | ❌ | "/tmp/capture.pcap" | Output file |

### dns_anomaly_check

Cek anomali DNS (tunneling, DGA).

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `interface` | string | ❌ | "eth0" | Network interface |
| `duration` | integer | ❌ | 60 | Durasi capture |

### hash_verify

Hitung hash file.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `filepath` | string | ✅ | - | Path file |

### baseline_compare

Bandingkan state saat ini dengan baseline.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `directory` | string | ✅ | - | Direktori untuk dicek |

---

## 13. Forensic — Digital Investigation (11)

### disk_image

Buat forensic disk image.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `source` | string | ✅ | - | Source device (contoh: /dev/sda1) |
| `destination` | string | ✅ | - | Path output file |

### file_recovery

Recovery file yang terhapus.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `image_path` | string | ✅ | - | Path disk image |
| `output_dir` | string | ❌ | "/tmp/recovered" | Direktori output |

### memory_dump

Dump live memory.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `output_path` | string | ✅ | - | Path output file |

### memory_analysis

Analisis memory dump dengan Volatility.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `dump_path` | string | ✅ | - | Path memory dump |
| `command` | string | ✅ | - | Volatility command: pslist, netscan, malfind, dlllist, cmdline, filescan |

### metadata_extract

Ekstrak metadata file.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `filepath` | string | ✅ | - | Path file |

### string_extract

Ekstrak strings dari binary.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `filepath` | string | ✅ | - | Path file |
| `min_length` | integer | ❌ | 4 | Panjang string minimum |

### binwalk_analysis

Analisis firmware/embedded files.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `filepath` | string | ✅ | - | Path file |

### log_timeline

Buat unified timeline dari logs.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `hours` | integer | ❌ | 24 | Jam untuk dilihat ke belakang |

### browser_forensic

Ekstrak browser history.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `user` | string | ✅ | - | Username |

### pcap_analysis

Analisis network capture.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `pcap_file` | string | ✅ | - | Path file PCAP |
| `filter_expr` | string | ❌ | "" | Wireshark display filter |

### evidence_hash

Hash evidence untuk chain of custody.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `filepath` | string | ✅ | - | Path file evidence |

---

## 14. Threat Intelligence (5)

### virustotal_lookup

Cek file/URL/IP di VirusTotal.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `ioc_type` | string | ✅ | - | Tipe: hash, url, ip, domain |
| `value` | string | ✅ | - | Nilai untuk lookup |

### abuseipdb_check

Cek reputasi IP di AbuseIPDB.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `ip` | string | ✅ | - | Alamat IP |

### shodan_lookup

Search Shodan untuk info host.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `target` | string | ✅ | - | IP atau search query |

### nvd_cve_lookup

Lookup detail CVE dari NVD.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `cve_id` | string | ✅ | - | CVE ID (contoh: CVE-2021-44228) |

### threat_feed_check

Cek terhadap threat intelligence feeds.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `ioc` | string | ✅ | - | Nilai IOC |
| `ioc_type` | string | ✅ | - | Tipe: ip, domain, hash |

---

## 15. Vulnerability Assessment (4)

### cis_benchmark

Jalankan CIS Benchmark audit.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `profile` | string | ❌ | "level1" | Profile: level1, level2 |

### hardening_check

Cek system hardening.

### patch_audit

Audit system patches.

### config_audit

Audit file konfigurasi.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `service` | string | ✅ | - | Service: ssh, apache, nginx, mysql |

---

## 16. SecOps (5)

### security_health_check

Overall security health assessment.

### playbook_execute

Eksekusi IR playbook.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `playbook` | string | ✅ | - | Playbook: brute_force, malware, data_breach, web_attack |

### metrics_collect

Collect security metrics.

### compliance_check

Cek compliance posture.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `framework` | string | ✅ | - | Framework: pci-dss, hipaa, nist, iso27001 |

### alert_triage

Triage security alert.

| Parameter | Tipe | Wajib | Default | Deskripsi |
|-----------|------|-------|---------|-----------|
| `alert_type` | string | ✅ | - | Tipe alert |
| `details` | string | ✅ | - | Detail alert |
