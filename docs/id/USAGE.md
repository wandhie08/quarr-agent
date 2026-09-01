# PANDUAN PENGGUNAAN — QUARR Agent (M0–M21 Complete)

**73 tools | 21 Python files | 5 docs | Red Team + Blue Team + Forensic**

---

## Daftar Isi

1. [Prasyarat](#1-prasyarat)
2. [Instalasi & Konfigurasi](#2-instalasi--konfigurasi)
3. [Menjalankan Agent](#3-menjalankan-agent)
4. [Engagement Setup](#4-engagement-setup)
5. [Menggunakan Agent](#5-menggunakan-agent)
6. [Perintah CLI](#6-perintah-cli)
7. [Tools Lengkap (73 Tools)](#7-tools-lengkap-73-tools)
8. [Alur Otomatis per Skenario](#8-alur-otomatis-per-skenario)
9. [Fitur: Finding Validation (M4)](#9-fitur-finding-validation-m4)
10. [Fitur: Knowledge Base / RAG (M5)](#10-fitur-knowledge-base--rag-m5)
11. [Fitur: Advanced Agent (M6)](#11-fitur-advanced-agent-m6)
12. [Fitur: Reporting & Export (M7)](#12-fitur-reporting--export-m7)
13. [Fitur: Persistent State (M9)](#13-fitur-persistent-state-m9)
14. [Fitur: Attack Planner (M10)](#14-fitur-attack-planner-m10)
15. [Fitur: Retesting (M18)](#15-fitur-retesting-m18)
16. [Policy Engine](#16-policy-engine)
17. [Arsitektur Sistem](#17-arsitektur-sistem)
18. [Konfigurasi Lanjutan](#18-konfigurasi-lanjutan)
19. [Troubleshooting](#19-troubleshooting)

---

## 1. Prasyarat

### LLM Backend

| Backend | Kebutuhan | Default |
|---------|-----------|---------|
| **OpenAI** | API key + internet | gpt-4o-mini |
| **Ollama** | 10 GB disk, 8 GB RAM | WhiteRabbitNeo-Qwen-Coder-7B |

### Kali Linux Tools

**🔴 Red Team — Recon & Discovery:**
nmap, subfinder, whatweb, wafw00f, gobuster, katana, arjun

**🔴 Red Team — Vuln Scan & Exploit:**
nuclei, nikto, sslscan, wpscan, sqlmap, dalfox, commix, hydra, enum4linux, dnsenum

**🔴 Red Team — Mobile:**
apktool, jadx, adb, frida-tools, objection

**🔴 Red Team — Active Directory:**
python3-impacket, crackmapexec, bloodhound (pip), ldapdomaindump, hashcat

**🔵 Blue Team:**
iptables, ufw, ss, ps, systemctl, chkrootkit, rkhunter, yara, tcpdump

**🔍 Forensic:**
volatility3, foremost/scalpel, exiftool, binwalk, tshark, dcfldd, strings

> Kali Linux sudah punya sebagian besar. Install yang kurang: `apt install <tool>`.

---

## 2. Instalasi & Konfigurasi

```bash
cd quarr-agent
pip install -r requirements.txt
```

Edit `.env`:

```bash
# OpenAI (recommended)
OPENAI_API_KEY=sk-proj-xxx
OPENAI_MODEL=gpt-4o-mini

# Ollama (jika OPENAI_API_KEY kosong)
# OLLAMA_MODEL=WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B:latest
```

Verifikasi: `python3 -c "from tools import TOOL_REGISTRY; print(f'{len(TOOL_REGISTRY)} tools OK')"`

---

## 3. Menjalankan Agent

```bash
python3 main.py                                           # Auto-detect backend
OPENAI_API_KEY="" python3 main.py                         # Force Ollama
OPENAI_MODEL=gpt-4o python3 main.py                       # GPT-4o
```

---

## 4. Engagement Setup

Baru:
```
Assessment name: My Assessment
  + target: target.com
  + target: 10.10.10.0/24
  - exclude: 10.10.10.1
```

Atau resume sesi:
```
🔐 quarr> load
  1. [ENG-abc] Previous Pentest (5 findings)
Load session #: 1
```

---

## 5. Menggunakan Agent

### 🔴 Red Team (Offensive)

```
🔐 quarr> Pentest lengkap target.com
🔐 quarr> Pentest network 10.10.10.0/24
🔐 quarr> Analisis APK /tmp/app.apk
🔐 quarr> Pentest AD domain corp.local DC 10.10.10.10
🔐 quarr> Test SQL injection di https://target.com/page?id=1
```

### 🔵 Blue Team (Defensive)

```
🔐 quarr> Cek status keamanan server — firewall, koneksi, proses, users
🔐 quarr> Analisis auth.log cari brute-force attempts
🔐 quarr> Ada dugaan compromise. Investigasi semua indikator.
🔐 quarr> Block IP 185.220.101.34
🔐 quarr> Cek persistence mechanisms — cron, services, hidden files
```

### 🔍 Forensic (Investigation)

```
🔐 quarr> Buat timeline dari semua log 24 jam terakhir
🔐 quarr> Dump memory dan analisis proses
🔐 quarr> Analisis PCAP /tmp/capture.pcap
🔐 quarr> Recover deleted files dari /tmp/disk.raw
🔐 quarr> Hash evidence file /tmp/malware.exe untuk chain of custody
🔐 quarr> Extract browser history user victim
```

### 🧠 Planned Execution

```
🔐 quarr> plan Pentest web target.com
(review plan → approve → auto execute)
```

---

## 6. Perintah CLI

### Monitoring

| Command | Fungsi |
|---------|--------|
| `state` | Hosts, services, observations, findings |
| `findings` | Temuan + validasi status |
| `scope` | Engagement scope |
| `history` | Tool execution log |

### Reporting (M7)

| Command | Output |
|---------|--------|
| `report` | Executive summary (terminal) |
| `executive` | Export → `.md` |
| `technical` | Export → `.md` (full detail) |
| `export` | Export → `.json` |

### Session (M9)

| Command | Fungsi |
|---------|--------|
| `save` | Simpan (auto setiap run + quit) |
| `load` | Muat sesi sebelumnya |
| `sessions` | Daftar sesi tersimpan |

### Planning & Retest

| Command | Fungsi |
|---------|--------|
| `plan <objective>` | Generate attack plan → review → execute |
| `retest` | Status retest findings |
| `retest <id>` | Retest finding spesifik |

---

## 7. Tools Lengkap (73 Tools)

### 🔴 Recon (6)

| Tool | Kali | Fungsi |
|------|------|--------|
| `target_scope_check` | ping | Cek konektivitas |
| `network_discovery` | nmap -sn | Discover hosts |
| `service_enumeration` | nmap -sV | Services & versi |
| `subdomain_enum` | subfinder/amass | Subdomain enum |
| `web_fingerprint` | whatweb | Tech stack |
| `waf_detection` | wafw00f | Deteksi WAF |

### 🔴 Discovery (3)

| Tool | Kali | Fungsi |
|------|------|--------|
| `web_content_discovery` | gobuster | Brute-force dir/file |
| `web_crawl` | katana | Crawl endpoints |
| `parameter_discovery` | arjun | Hidden parameters |

### 🔴 Vulnerability Scanning (4)

| Tool | Kali | Fungsi |
|------|------|--------|
| `vulnerability_scan` | nuclei | CVE, misconfig |
| `web_vuln_scan` | nikto | Web server vuln |
| `ssl_scan` | sslscan | SSL/TLS audit |
| `cms_scan` | wpscan | WordPress vuln |

### 🔴 Exploitation (5)

| Tool | Kali | Fungsi | Risk |
|------|------|--------|------|
| `sqli_scan` | sqlmap | SQL injection | high |
| `xss_scan` | dalfox | XSS | high |
| `command_injection_scan` | commix | Command injection | high |
| `bruteforce_login` | hydra | Brute-force password | high |
| `exploit_search` | searchsploit | Cari exploit | low |

### 🔴 Network Enum (3)

| Tool | Kali | Fungsi |
|------|------|--------|
| `smb_enum` | enum4linux | SMB shares/users |
| `dns_enum` | dnsenum | DNS records |
| `snmp_enum` | snmpwalk | SNMP info |

### 🔴 Mobile Static (5)

| Tool | Kali | Fungsi |
|------|------|--------|
| `apk_decompile` | apktool+jadx | Decompile APK |
| `apk_secrets_scan` | grep | Hardcoded secrets |
| `apk_manifest_analysis` | parser | Manifest analysis |
| `apk_network_config` | parser | Network security config |
| `apk_cert_check` | apksigner | Signing certificate |

### 🔴 Mobile Dynamic (6)

| Tool | Kali | Fungsi |
|------|------|--------|
| `adb_device_check` | adb | Cek device |
| `adb_app_info` | adb | App info |
| `adb_storage_check` | adb | Plaintext storage |
| `adb_logcat_check` | adb | Sensitive logs |
| `frida_ssl_bypass` | frida | Bypass SSL pinning |
| `objection_explore` | objection | Runtime exploration |

### 🔴 AD Attack (7)

| Tool | Kali | Fungsi | Risk |
|------|------|--------|------|
| `kerberos_asrep_roast` | impacket | AS-REP Roasting | high |
| `kerberos_kerberoast` | impacket | Kerberoasting | high |
| `secrets_dump` | impacket | Dump SAM/NTDS | critical |
| `psexec` | impacket | Remote exec (SMB) | critical |
| `wmiexec` | impacket | Remote exec (WMI) | critical |
| `password_spray` | crackmapexec | Password spray | high |
| `hash_crack` | hashcat | Crack hashes | low |

### 🔴 AD Enum (4)

| Tool | Kali | Fungsi |
|------|------|--------|
| `ldap_search` | ldapsearch | LDAP users/groups |
| `ldap_domain_dump` | ldapdomaindump | Full domain dump |
| `bloodhound_collect` | bloodhound-py | BloodHound data |
| `rpc_enum` | rpcclient | RPC enum (null session) |

### 🔵 Blue Team Defense (11)

| Tool | Kali | Fungsi |
|------|------|--------|
| `firewall_status` | iptables/ufw | Cek firewall rules |
| `firewall_block` | iptables | Block IP |
| `firewall_unblock` | iptables | Unblock IP |
| `log_analysis` | tail/grep | Analisis logs (auth/syslog/kern/ufw/fail2ban/apache/nginx) |
| `active_connections` | ss | Koneksi aktif (all/established/listening/suspicious) |
| `port_audit` | ss -tulpn | Audit ports — deteksi backdoor |
| `process_monitor` | ps | Monitor proses — reverse shell, miner |
| `service_audit` | systemctl | Services running + enabled |
| `user_audit` | last/who | Login history, failed, sudo, shells |
| `cron_audit` | crontab | Cron jobs — persistence |
| `file_integrity_check` | find | File modified + SUID binaries |

### 🔵 Threat Hunting (8)

| Tool | Kali | Fungsi |
|------|------|--------|
| `ioc_search` | grep/find | Cari IOC (IP, domain, hash, filename, string) |
| `suspicious_files` | find | File baru/hidden/executable di temp |
| `rootkit_scan` | chkrootkit/rkhunter | Scan rootkit |
| `yara_scan` | yara | Scan malware dengan YARA rules |
| `network_capture` | tcpdump | Capture packets |
| `dns_anomaly_check` | tcpdump | DNS tunneling, DGA domains |
| `hash_verify` | sha256sum | Hash file |
| `baseline_compare` | diff/sha256 | Bandingkan vs baseline |

### 🔍 Digital Forensic (11)

| Tool | Kali | Fungsi |
|------|------|--------|
| `disk_image` | dcfldd/dd | Forensic disk image |
| `file_recovery` | foremost/scalpel | Recover deleted files |
| `memory_dump` | avml/LiME | Dump live RAM |
| `memory_analysis` | volatility3 | Analisis memory (pslist/netscan/malfind/dll) |
| `metadata_extract` | exiftool | Extract metadata |
| `string_extract` | strings | Extract strings binary |
| `binwalk_analysis` | binwalk | Analisis firmware |
| `log_timeline` | custom | Unified timeline semua logs |
| `browser_forensic` | sqlite3 | Browser history Firefox/Chrome |
| `pcap_analysis` | tshark | Analisis PCAP (protocols, DNS, HTTP) |
| `evidence_hash` | md5/sha1/sha256 | Hash evidence — chain of custody |

---

## 8. Alur Otomatis per Skenario

### 🔴 Web Application

```
scope_check → service_enum → fingerprint → waf → content_discovery →
crawl → vuln_scan → sqli → xss → command_injection → Report
```

### 🔴 Network

```
discovery → service_enum (×N) → smb → dns → snmp →
vuln_scan → bruteforce → exploit_search → Report
```

### 🔴 Mobile APK

```
decompile → manifest → network_config → cert → secrets → [test API] → Report
```

### 🔴 Active Directory

```
discovery → service_enum → ldap → rpc → bloodhound →
asrep → kerberoast → spray → secretsdump → Report
```

### 🔵 Incident Response

```
active_connections(suspicious) → process_monitor → port_audit →
user_audit → cron_audit → file_integrity → log_analysis →
suspicious_files → log_timeline → Report
```

### 🔵 Threat Hunting

```
suspicious_files → rootkit_scan → baseline_compare → dns_anomaly →
active_connections → cron_audit → service_audit → Report
```

### 🔍 Post-Incident Forensic

```
evidence_hash → memory_dump → memory_analysis(pslist) →
memory_analysis(netscan) → memory_analysis(malfind) →
log_timeline → browser_forensic → pcap_analysis → Report
```

---

## 9. Fitur: Finding Validation (M4)

```
OBSERVATION → HYPOTHESIS → DETECTED → VALIDATING → CONFIRMED → REPORTED
```

Otomatis setelah setiap tool. CWE auto-enriched saat CONFIRMED.

---

## 10. Fitur: Knowledge Base / RAG (M5)

| Source | Entries |
|--------|---------|
| OWASP WSTG | 17 web testing guides |
| OWASP API Top 10 | 5 API security entries |
| OWASP Mobile Top 10 | 10 mobile entries |
| CWE Database | 10 weakness definitions |
| CVSS Reference | 5 severity levels |
| NIST SP 800-61 | 7 IR phases |
| NIST SP 800-86 | Forensic guidelines |
| MITRE ATT&CK | 10 techniques + detection |
| Tech/Service Tips | WordPress, Apache, IIS, PHP, SMB, SSH, FTP, MySQL |

Context-aware: dipilih berdasarkan fase + services + teknologi + query.

---

## 11. Fitur: Advanced Agent (M6)

- Phase detection (recon → discovery → vuln_scan → exploit)
- Failure recovery (skip failed tools, try alternative)
- Smart context (parsed results + state + knowledge + validation)

---

## 12. Fitur: Reporting & Export (M7)

| Command | Format | Isi |
|---------|--------|-----|
| `report` | Terminal | Risk rating, top findings |
| `executive` | Markdown | Non-teknis untuk management |
| `technical` | Markdown | Full: findings + CVSS + CWE + evidence + tools + observations |
| `export` | JSON | Machine-readable |

---

## 13. Fitur: Persistent State (M9)

Auto-save setiap run + quit. File: `engagements/<id>/state.json`

```
🔐 quarr> save         ← manual save
🔐 quarr> load         ← resume sesi
🔐 quarr> sessions     ← list semua
```

---

## 14. Fitur: Attack Planner (M10)

```
🔐 quarr> plan Pentest web target.com
📋 ATTACK PLAN (6 steps)
  ⬜ 1. target_scope_check → 2. service_enumeration → ...
Approve plan? (y/n): y
✅ Executing...
```

---

## 15. Fitur: Retesting (M18)

```
🔐 quarr> retest                    ← status semua findings
🔐 quarr> retest SQL Injection      ← retest finding spesifik
```

---

## 16. Policy Engine

Setiap tool call divalidasi. URL auto-extract hostname.

```
https://target.com/api?id=1 → target.com → match scope
```

---

## 17. Arsitektur Sistem

```
User
 ├── plan (M10) → LLM plan → approve → execute
 ├── Red Team query → agent loop → 43 tools
 ├── Blue Team query → agent loop → 19 tools
 ├── Forensic query → agent loop → 11 tools
 │
 └── agent.py loop:
     Context (M5 knowledge) → LLM → Tool Call →
     Policy → Execute → Parse → State Update →
     Validate (M4) → Evidence (M17) → Loop/Return
     
 ├── report/export (M7) → reporter.py
 ├── save/load (M9) → persistence.py
 └── retest (M18) → retest.py
```

### Files (21 Python + 5 Docs)

| File | Milestone | Fungsi |
|------|-----------|--------|
| `models.py` | M1 | Pydantic state |
| `policy.py` | M1 | Scope authorization |
| `tools.py` | M1-M21 | 73 tool registry |
| `parsers.py` | M1-M3 | Output parsers |
| `llm_client.py` | M0 | Ollama + OpenAI |
| `knowledge.py` | M5 | OWASP/CWE/MITRE/NIST |
| `validator.py` | M4 | Finding validation |
| `reporter.py` | M7 | Report generation |
| `mobile_tools.py` | M8 | 11 mobile handlers |
| `mobile_parsers.py` | M8 | Mobile parsers |
| `ad_tools.py` | M12 | 11 AD/Impacket handlers |
| `blue_team_tools.py` | M19 | 11 defense handlers |
| `threat_hunting_tools.py` | M20 | 8 hunting handlers |
| `forensic_tools.py` | M21 | 11 forensic handlers |
| `persistence.py` | M9 | Save/load state |
| `planner.py` | M10 | Attack planner |
| `evidence.py` | M17 | Evidence collection |
| `benchmark.py` | M13 | Metrics framework |
| `retest.py` | M18 | Retesting engine |
| `agent.py` | All | Core agentic loop |
| `main.py` | All | CLI entrypoint |

---

## 18. Konfigurasi Lanjutan

### .env

```
OPENAI_API_KEY=sk-proj-xxx
OPENAI_MODEL=gpt-4o-mini
```

### Max Steps

`agent.py`: `MAX_AGENT_STEPS = 15`

### Logging

```bash
tail -f quarr.log
```

---

## 19. Troubleshooting

| Masalah | Solusi |
|---------|--------|
| LLM error | Cek API key / Ollama status |
| Command not found | Install tool: `apt install <tool>`. Agent skip & lanjut (M6) |
| Finding stuck | Jalankan lebih banyak tools atau minta validasi eksplisit |
| Session hilang | Auto-save aktif (M9). Cek `sessions` |
| Policy violation | Cek `scope`. Tambahkan target yang diperlukan |
