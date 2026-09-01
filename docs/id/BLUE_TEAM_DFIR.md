# PANDUAN BLUE TEAM & DIGITAL FORENSIC — QUARR Agent

## Daftar Isi

1. [Overview](#1-overview)
2. [M19 — Blue Team Defense & Monitoring](#2-m19--blue-team-defense--monitoring)
3. [M20 — Threat Hunting & Detection](#3-m20--threat-hunting--detection)
4. [M21 — Digital Forensic](#4-m21--digital-forensic)
5. [Skenario: Incident Response](#5-skenario-incident-response)
6. [Skenario: Threat Hunting Proaktif](#6-skenario-threat-hunting-proaktif)
7. [Skenario: Post-Incident Forensic](#7-skenario-post-incident-forensic)
8. [Knowledge Base](#8-knowledge-base)

---

## 1. Overview

QUARR sekarang bisa digunakan untuk 3 fungsi:

| Role | Tools | Fungsi |
|------|-------|--------|
| 🔴 **Red Team** | 43 tools | Offensive pentest (web, network, mobile, AD) |
| 🔵 **Blue Team** | 19 tools | Defensive monitoring, hardening, incident response |
| 🔍 **Forensic** | 11 tools | Investigasi pasca-insiden, evidence preservation |

---

## 2. M19 — Blue Team Defense & Monitoring

### Tools (11)

| Tool | Fungsi |
|------|--------|
| `firewall_status` | Cek firewall rules (iptables + UFW) |
| `firewall_block` | Block IP di firewall |
| `firewall_unblock` | Unblock IP |
| `log_analysis` | Analisis auth.log, syslog, kern, ufw, fail2ban, apache, nginx |
| `active_connections` | Cek koneksi aktif (all/established/listening/suspicious) |
| `port_audit` | Audit listening ports — deteksi backdoor |
| `process_monitor` | Monitor proses — deteksi reverse shell, miner |
| `service_audit` | Audit systemd services (running + enabled) |
| `user_audit` | Audit users: sessions, logins, failed, sudo, shells |
| `cron_audit` | Audit cron jobs — deteksi persistence |
| `file_integrity_check` | Cek file modified + SUID binaries |

### Contoh Penggunaan

**Situational awareness (pertama kali login ke server):**

```
🔐 quarr> Cek status keamanan server ini — firewall, koneksi aktif, proses, users

⚙️ firewall_status()
⚙️ active_connections(filter_type=suspicious)
⚙️ process_monitor()
⚙️ user_audit()
⚙️ port_audit()
```

**Detect compromise:**

```
🔐 quarr> Ada dugaan server dicompromise. Cek semua indikator:
            koneksi suspicious, proses mencurigakan, cron persistence, file yang berubah

⚙️ active_connections(filter_type=suspicious)
⚙️ process_monitor()
⚙️ cron_audit()
⚙️ file_integrity_check(directory=/usr/bin, days=3)
```

**Block attacker:**

```
🔐 quarr> Block IP 185.220.101.34 di firewall

⚙️ firewall_block(ip_address=185.220.101.34)
✅ Blocked: 185.220.101.34
```

**Log analysis:**

```
🔐 quarr> Analisis auth.log, cari failed login attempts

⚙️ log_analysis(log_type=auth, filter_pattern=Failed)

🔐 quarr> Analisis apache access log, cari SQL injection attempts

⚙️ log_analysis(log_type=apache, filter_pattern=select|union|drop)
```

---

## 3. M20 — Threat Hunting & Detection

### Tools (8)

| Tool | Fungsi |
|------|--------|
| `ioc_search` | Cari IOC di sistem (IP, domain, hash, filename, string) |
| `suspicious_files` | Cari file baru, hidden, executable di temp dirs |
| `rootkit_scan` | Scan rootkit (chkrootkit + rkhunter) |
| `yara_scan` | Scan malware dengan YARA rules |
| `network_capture` | Capture network packets |
| `dns_anomaly_check` | Deteksi DNS tunneling, DGA domains |
| `hash_verify` | Hitung SHA256 hash file |
| `baseline_compare` | Bandingkan state saat ini vs baseline |

### Contoh Penggunaan

**IOC search (dari threat intel feed):**

```
🔐 quarr> Cari IOC: IP 185.220.101.34 di sistem ini

⚙️ ioc_search(ioc_type=ip, value=185.220.101.34)
→ Ditemukan di auth.log: 15 failed login attempts
→ Ditemukan di ss: ESTABLISHED connection ke port 4444

🔐 quarr> Cari file dengan hash a1b2c3d4e5f6...

⚙️ ioc_search(ioc_type=hash, value=a1b2c3d4e5f6...)
```

**Suspicious file hunting:**

```
🔐 quarr> Cari file mencurigakan di /tmp dan /dev/shm

⚙️ suspicious_files(directory=/tmp, days=3)
⚙️ suspicious_files(directory=/dev/shm, days=3)
→ ⚠️ Hidden file: /tmp/.x11-unix-backdoor
→ ⚠️ Executable: /dev/shm/shell.elf
```

**Rootkit detection:**

```
🔐 quarr> Scan rootkit di server ini

⚙️ rootkit_scan()
→ chkrootkit: Checking... INFECTED (Suckit)
→ rkhunter: Warning: suspicious file /usr/bin/dir
```

**DNS tunneling detection:**

```
🔐 quarr> Cek apakah ada DNS tunneling di network

⚙️ dns_anomaly_check(interface=eth0)
→ ⚠️ Long domain (possible tunneling): aGVsbG8gd29ybGQ.evil-dns.com
→ ⚠️ TXT query: suspicious.domain.com
```

**Baseline comparison:**

```
🔐 quarr> Buat baseline /usr/bin dan bandingkan

⚙️ baseline_compare(directory=/usr/bin)
→ ✅ Baseline created: 1523 files

(setelah beberapa waktu...)

🔐 quarr> Bandingkan /usr/bin dengan baseline

⚙️ baseline_compare(directory=/usr/bin)
→ ⚠️ CHANGED: /usr/bin/sudo (hash berbeda!)
→ ⚠️ NEW: /usr/bin/backdoor
```

---

## 4. M21 — Digital Forensic

### Tools (11)

| Tool | Fungsi |
|------|--------|
| `disk_image` | Buat forensic disk image (dcfldd/dd) |
| `file_recovery` | Recover deleted files (foremost/scalpel) |
| `memory_dump` | Dump live RAM |
| `memory_analysis` | Analisis memory dump (Volatility 3) |
| `metadata_extract` | Extract metadata file (exiftool) |
| `string_extract` | Extract strings dari binary |
| `binwalk_analysis` | Analisis firmware/embedded files |
| `log_timeline` | Unified timeline dari semua logs |
| `browser_forensic` | Extract browser history (Firefox/Chrome) |
| `pcap_analysis` | Analisis network capture (protocols, DNS, HTTP) |
| `evidence_hash` | Hash evidence (MD5 + SHA1 + SHA256) chain of custody |

### Contoh Penggunaan

**Memory forensics:**

```
🔐 quarr> Dump memory dan analisis proses yang berjalan

⚙️ memory_dump(output_path=/tmp/memory.raw)
⚙️ memory_analysis(dump_path=/tmp/memory.raw, command=pslist)
⚙️ memory_analysis(dump_path=/tmp/memory.raw, command=netscan)
⚙️ memory_analysis(dump_path=/tmp/memory.raw, command=malfind)
```

**Timeline reconstruction:**

```
🔐 quarr> Buat timeline dari semua log 24 jam terakhir

⚙️ log_timeline(hours=24)
→ [AUTH] Aug 30 02:15 Failed password for root from 185.220.101.34
→ [AUTH] Aug 30 02:15 Accepted password for www-data from 185.220.101.34
→ [SYSTEM] Aug 30 02:16 Started new session
→ [APACHE] Aug 30 02:17 POST /shell.php 200
→ [KERNEL] Aug 30 02:18 process 'nc' started
```

**Disk forensics:**

```
🔐 quarr> Buat forensic image dari /dev/sda1

⚙️ disk_image(source=/dev/sda1, destination=/evidence/disk.raw)

🔐 quarr> Recover deleted files dari image

⚙️ file_recovery(image_path=/evidence/disk.raw)
→ Recovered: 15 files (3 jpg, 5 pdf, 2 doc, 5 txt)
```

**Network forensics:**

```
🔐 quarr> Analisis PCAP file /tmp/capture.pcap

⚙️ pcap_analysis(pcap_file=/tmp/capture.pcap)
→ Protocol hierarchy: TCP 85%, UDP 10%, ICMP 5%
→ Top conversations: 10.0.0.5 ↔ 185.220.101.34 (5.2 MB)
→ DNS queries: evil-c2.com (47 queries), update.malware.cc
→ HTTP: POST /gate.php, GET /payload.exe

🔐 quarr> Filter PCAP untuk traffic ke 185.220.101.34

⚙️ pcap_analysis(pcap_file=/tmp/capture.pcap, filter_expr=ip.addr==185.220.101.34)
```

**Evidence preservation:**

```
🔐 quarr> Hash evidence file untuk chain of custody

⚙️ evidence_hash(filepath=/evidence/malware.exe)
→ MD5:    d41d8cd98f00b204e9800998ecf8427e
→ SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
→ SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
→ File type: PE32 executable (GUI) Intel 80386
→ Timestamp: 2026-08-30T08:30:00
```

**Browser forensics:**

```
🔐 quarr> Extract browser history dari user compromised

⚙️ browser_forensic(user=victim)
→ FIREFOX HISTORY:
→   2026-08-30 02:10 http://evil-site.com/exploit.html
→   2026-08-30 02:11 http://evil-site.com/download/payload.exe
→ CHROME HISTORY:
→   2026-08-30 01:55 http://phishing-bank.com/login
```

---

## 5. Skenario: Incident Response

### Situasi: Server diduga dicompromise

```
🔐 quarr> Lakukan incident response pada server ini.
            Ada dugaan compromise dari alert monitoring.

Agent otomatis menjalankan:

1. active_connections(suspicious)     ← ada koneksi ke C2?
2. process_monitor()                  ← ada reverse shell? miner?
3. port_audit()                       ← ada backdoor listening?
4. user_audit()                       ← login anomaly?
5. cron_audit()                       ← persistence via cron?
6. file_integrity_check(/usr/bin, 3)  ← binary dimodifikasi?
7. log_analysis(auth, Failed)         ← brute-force?
8. suspicious_files(/tmp, 3)          ← malware di /tmp?
9. log_timeline(24)                   ← timeline insiden
→ Report + Findings

🔐 quarr> Block attacker IP 185.220.101.34

⚙️ firewall_block(185.220.101.34)

🔐 quarr> technical
✅ Exported: report_technical_*.md
```

### Step-by-step (NIST SP 800-61)

```
# 1. DETECTION
🔐 quarr> Cek koneksi suspicious dan proses mencurigakan

# 2. ANALYSIS
🔐 quarr> Analisis auth.log 48 jam terakhir, buat timeline

# 3. CONTAINMENT
🔐 quarr> Block IP 185.220.101.34 di firewall

# 4. ERADICATION
🔐 quarr> Cari persistence: cron jobs, services, hidden files

# 5. RECOVERY
🔐 quarr> Verify file integrity /usr/bin, bandingkan baseline

# 6. DOCUMENTATION
🔐 quarr> technical
🔐 quarr> export
```

---

## 6. Skenario: Threat Hunting Proaktif

### Situasi: Hunting tanpa alert/insiden spesifik

```
🔐 quarr> Lakukan proactive threat hunting di server ini.
            Cari indikator kompromi, persistence, anomaly.

Agent otomatis:

1. suspicious_files(/tmp, 7)            ← file baru di temp?
2. suspicious_files(/dev/shm, 7)        ← executable di shared memory?
3. rootkit_scan()                        ← rootkit?
4. cron_audit()                          ← cron persistence?
5. service_audit()                       ← service asing?
6. baseline_compare(/usr/bin)            ← binary berubah?
7. dns_anomaly_check()                   ← DNS tunneling?
8. active_connections(suspicious)        ← C2 connections?
→ Report

🔐 quarr> Scan YARA rules di /home /tmp /var

⚙️ yara_scan(directory=/home)
⚙️ yara_scan(directory=/tmp)

🔐 quarr> Cari IOC dari threat feed: domain evil-c2.com

⚙️ ioc_search(ioc_type=domain, value=evil-c2.com)
```

---

## 7. Skenario: Post-Incident Forensic

### Situasi: Investigasi setelah breach dikonfirmasi

```
# PRESERVE EVIDENCE
🔐 quarr> Hash semua evidence files

⚙️ evidence_hash(filepath=/tmp/suspicious_binary)
⚙️ evidence_hash(filepath=/var/log/auth.log)

# MEMORY
🔐 quarr> Dump dan analisis memory

⚙️ memory_dump(output_path=/evidence/memory.raw)
⚙️ memory_analysis(dump_path=/evidence/memory.raw, command=pslist)
⚙️ memory_analysis(dump_path=/evidence/memory.raw, command=netscan)
⚙️ memory_analysis(dump_path=/evidence/memory.raw, command=malfind)

# TIMELINE
🔐 quarr> Buat timeline 72 jam terakhir

⚙️ log_timeline(hours=72)

# FILE ANALYSIS
🔐 quarr> Analisis file mencurigakan

⚙️ metadata_extract(filepath=/tmp/.hidden_binary)
⚙️ string_extract(filepath=/tmp/.hidden_binary)
⚙️ binwalk_analysis(filepath=/tmp/.hidden_binary)

# NETWORK
🔐 quarr> Analisis PCAP yang sudah di-capture

⚙️ pcap_analysis(pcap_file=/evidence/network.pcap)

# BROWSER
🔐 quarr> Extract browser history user yang tercompromise

⚙️ browser_forensic(user=victim)

# DISK
🔐 quarr> Buat forensic image dan recover deleted files

⚙️ disk_image(source=/dev/sda1, destination=/evidence/disk.raw)
⚙️ file_recovery(image_path=/evidence/disk.raw)

# REPORT
🔐 quarr> technical
🔐 quarr> export
```

---

## 8. Knowledge Base

Agent (M5) otomatis inject knowledge relevan saat konteks blue team/forensic terdeteksi:

### NIST SP 800-61 (Incident Response)

```
Preparation → Detection → Analysis → Containment →
Eradication → Recovery → Lessons Learned
```

### MITRE ATT&CK (10 techniques)

| ID | Technique | Tactic | Detect With |
|----|-----------|--------|-------------|
| T1059 | Command Interpreter | Execution | process_monitor |
| T1053 | Scheduled Task | Persistence | cron_audit |
| T1078 | Valid Accounts | Persistence | user_audit, log_analysis |
| T1110 | Brute Force | Credential Access | log_analysis(auth, Failed) |
| T1048 | Exfil Alt Protocol | Exfiltration | dns_anomaly_check |
| T1071 | App Layer Protocol | C2 | pcap_analysis |
| T1547 | Autostart Execution | Persistence | service_audit |
| T1070 | Indicator Removal | Defense Evasion | log_timeline, file_integrity |
| T1003 | Credential Dumping | Credential Access | memory_analysis(malfind) |
| T1105 | Ingress Tool Transfer | C2 | suspicious_files |

### NIST SP 800-86 (Digital Forensic)

- Preserve evidence integrity (hash before & after)
- Maintain chain of custody
- Order of volatility: RAM → disk cache → disk → logs → backups
- Document every action
