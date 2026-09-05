# BLUE TEAM & DIGITAL FORENSIC GUIDE — QUARR Agent

## Table of Contents

1. [Overview](#1-overview)
2. [M19 — Blue Team Defense & Monitoring](#2-m19--blue-team-defense--monitoring)
3. [M20 — Threat Hunting & Detection](#3-m20--threat-hunting--detection)
4. [M21 — Digital Forensic](#4-m21--digital-forensic)
5. [Scenario: Incident Response](#5-scenario-incident-response)
6. [Scenario: Proactive Threat Hunting](#6-scenario-proactive-threat-hunting)
7. [Scenario: Post-Incident Forensic](#7-scenario-post-incident-forensic)
8. [Knowledge Base](#8-knowledge-base)
9. [Testing the Blue Team Scenarios](#9-testing-the-blue-team-scenarios)

---

## 1. Overview

QUARR can now be used for 3 functions:

| Role | Tools | Function |
|------|-------|----------|
| 🔴 **Red Team** | 43 tools | Offensive pentest (web, network, mobile, AD) |
| 🔵 **Blue Team** | 19 tools | Defensive monitoring, hardening, incident response |
| 🔍 **Forensic** | 11 tools | Post-incident investigation, evidence preservation |

---

## 2. M19 — Blue Team Defense & Monitoring

### Tools (11)

| Tool | Function |
|------|----------|
| `firewall_status` | Check firewall rules (iptables + UFW) |
| `firewall_block` | Block IP in firewall |
| `firewall_unblock` | Unblock IP |
| `log_analysis` | Analyze auth.log, syslog, kern, ufw, fail2ban, apache, nginx |
| `active_connections` | Check active connections (all/established/listening/suspicious) |
| `port_audit` | Audit listening ports — detect backdoor |
| `process_monitor` | Monitor processes — detect reverse shell, miner |
| `service_audit` | Audit systemd services (running + enabled) |
| `user_audit` | Audit users: sessions, logins, failed, sudo, shells |
| `cron_audit` | Audit cron jobs — detect persistence |
| `file_integrity_check` | Check modified files + SUID binaries |

### Usage Examples

**Situational awareness (first login to server):**

```
🔐 quarr> Check this server's security status — firewall, active connections, processes, users

⚙️ firewall_status()
⚙️ active_connections(filter_type=suspicious)
⚙️ process_monitor()
⚙️ user_audit()
⚙️ port_audit()
```

**Detect compromise:**

```
🔐 quarr> Server suspected compromised. Check all indicators:
            suspicious connections, suspicious processes, cron persistence, modified files

⚙️ active_connections(filter_type=suspicious)
⚙️ process_monitor()
⚙️ cron_audit()
⚙️ file_integrity_check(directory=/usr/bin, days=3)
```

**Block attacker:**

```
🔐 quarr> Block IP 185.220.101.34 in firewall

⚙️ firewall_block(ip_address=185.220.101.34)
✅ Blocked: 185.220.101.34
```

**Log analysis:**

```
🔐 quarr> Analyze auth.log, search for failed login attempts

⚙️ log_analysis(log_type=auth, filter_pattern=Failed)

🔐 quarr> Analyze apache access log, search for SQL injection attempts

⚙️ log_analysis(log_type=apache, filter_pattern=select|union|drop)
```

---

## 3. M20 — Threat Hunting & Detection

### Tools (8)

| Tool | Function |
|------|----------|
| `ioc_search` | Search IOC in system (IP, domain, hash, filename, string) |
| `suspicious_files` | Search new, hidden, executable files in temp dirs |
| `rootkit_scan` | Rootkit scan (chkrootkit + rkhunter) |
| `yara_scan` | Malware scan with YARA rules |
| `network_capture` | Capture network packets |
| `dns_anomaly_check` | Detect DNS tunneling, DGA domains |
| `hash_verify` | Calculate SHA256 file hash |
| `baseline_compare` | Compare current state vs baseline |

### Usage Examples

**IOC search (from threat intel feed):**

```
🔐 quarr> Search IOC: IP 185.220.101.34 on this system

⚙️ ioc_search(ioc_type=ip, value=185.220.101.34)
→ Found in auth.log: 15 failed login attempts
→ Found in ss: ESTABLISHED connection to port 4444

🔐 quarr> Search file with hash a1b2c3d4e5f6...

⚙️ ioc_search(ioc_type=hash, value=a1b2c3d4e5f6...)
```

**Suspicious file hunting:**

```
🔐 quarr> Search suspicious files in /tmp and /dev/shm

⚙️ suspicious_files(directory=/tmp, days=3)
⚙️ suspicious_files(directory=/dev/shm, days=3)
→ ⚠️ Hidden file: /tmp/.x11-unix-backdoor
→ ⚠️ Executable: /dev/shm/shell.elf
```

**Rootkit detection:**

```
🔐 quarr> Rootkit scan on this server

⚙️ rootkit_scan()
→ chkrootkit: Checking... INFECTED (Suckit)
→ rkhunter: Warning: suspicious file /usr/bin/dir
```

**DNS tunneling detection:**

```
🔐 quarr> Check for DNS tunneling on network

⚙️ dns_anomaly_check(interface=eth0)
→ ⚠️ Long domain (possible tunneling): aGVsbG8gd29ybGQ.evil-dns.com
→ ⚠️ TXT query: suspicious.domain.com
```

**Baseline comparison:**

```
🔐 quarr> Create baseline for /usr/bin and compare

⚙️ baseline_compare(directory=/usr/bin)
→ ✅ Baseline created: 1523 files

(after some time...)

🔐 quarr> Compare /usr/bin with baseline

⚙️ baseline_compare(directory=/usr/bin)
→ ⚠️ CHANGED: /usr/bin/sudo (hash different!)
→ ⚠️ NEW: /usr/bin/backdoor
```

---

## 4. M21 — Digital Forensic

### Tools (11)

| Tool | Function |
|------|----------|
| `disk_image` | Create forensic disk image (dcfldd/dd) |
| `file_recovery` | Recover deleted files (foremost/scalpel) |
| `memory_dump` | Dump live RAM |
| `memory_analysis` | Memory dump analysis (Volatility 3) |
| `metadata_extract` | Extract file metadata (exiftool) |
| `string_extract` | Extract strings from binary |
| `binwalk_analysis` | Firmware/embedded files analysis |
| `log_timeline` | Unified timeline from all logs |
| `browser_forensic` | Extract browser history (Firefox/Chrome) |
| `pcap_analysis` | Network capture analysis (protocols, DNS, HTTP) |
| `evidence_hash` | Hash evidence (MD5 + SHA1 + SHA256) chain of custody |

### Usage Examples

**Memory forensics:**

```
🔐 quarr> Dump memory and analyze running processes

⚙️ memory_dump(output_path=/tmp/memory.raw)
⚙️ memory_analysis(dump_path=/tmp/memory.raw, command=pslist)
⚙️ memory_analysis(dump_path=/tmp/memory.raw, command=netscan)
⚙️ memory_analysis(dump_path=/tmp/memory.raw, command=malfind)
```

**Timeline reconstruction:**

```
🔐 quarr> Create timeline from all logs last 24 hours

⚙️ log_timeline(hours=24)
→ [AUTH] Aug 30 02:15 Failed password for root from 185.220.101.34
→ [AUTH] Aug 30 02:15 Accepted password for www-data from 185.220.101.34
→ [SYSTEM] Aug 30 02:16 Started new session
→ [APACHE] Aug 30 02:17 POST /shell.php 200
→ [KERNEL] Aug 30 02:18 process 'nc' started
```

**Disk forensics:**

```
🔐 quarr> Create forensic image from /dev/sda1

⚙️ disk_image(source=/dev/sda1, destination=/evidence/disk.raw)

🔐 quarr> Recover deleted files from image

⚙️ file_recovery(image_path=/evidence/disk.raw)
→ Recovered: 15 files (3 jpg, 5 pdf, 2 doc, 5 txt)
```

**Network forensics:**

```
🔐 quarr> Analyze PCAP file /tmp/capture.pcap

⚙️ pcap_analysis(pcap_file=/tmp/capture.pcap)
→ Protocol hierarchy: TCP 85%, UDP 10%, ICMP 5%
→ Top conversations: 10.0.0.5 ↔ 185.220.101.34 (5.2 MB)
→ DNS queries: evil-c2.com (47 queries), update.malware.cc
→ HTTP: POST /gate.php, GET /payload.exe

🔐 quarr> Filter PCAP for traffic to 185.220.101.34

⚙️ pcap_analysis(pcap_file=/tmp/capture.pcap, filter_expr=ip.addr==185.220.101.34)
```

**Evidence preservation:**

```
🔐 quarr> Hash evidence file for chain of custody

⚙️ evidence_hash(filepath=/evidence/malware.exe)
→ MD5:    d41d8cd98f00b204e9800998ecf8427e
→ SHA1:   da39a3ee5e6b4b0d3255bfef95601890afd80709
→ SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
→ File type: PE32 executable (GUI) Intel 80386
→ Timestamp: 2026-08-30T08:30:00
```

**Browser forensics:**

```
🔐 quarr> Extract browser history from compromised user

⚙️ browser_forensic(user=victim)
→ FIREFOX HISTORY:
→   2026-08-30 02:10 http://evil-site.com/exploit.html
→   2026-08-30 02:11 http://evil-site.com/download/payload.exe
→ CHROME HISTORY:
→   2026-08-30 01:55 http://phishing-bank.com/login
```

---

## 5. Scenario: Incident Response

### Situation: Server suspected compromised

```
🔐 quarr> Perform incident response on this server.
            Suspected compromise from monitoring alert.

Agent automatically runs:

1. active_connections(suspicious)     ← connection to C2?
2. process_monitor()                  ← reverse shell? miner?
3. port_audit()                       ← backdoor listening?
4. user_audit()                       ← login anomaly?
5. cron_audit()                       ← persistence via cron?
6. file_integrity_check(/usr/bin, 3)  ← binary modified?
7. log_analysis(auth, Failed)         ← brute-force?
8. suspicious_files(/tmp, 3)          ← malware in /tmp?
9. log_timeline(24)                   ← incident timeline
→ Report + Findings

🔐 quarr> Block attacker IP 185.220.101.34

⚙️ firewall_block(185.220.101.34)

🔐 quarr> technical
✅ Exported: report_technical_*.md
```

### Step-by-step (NIST SP 800-61)

```
# 1. DETECTION
🔐 quarr> Check suspicious connections and suspicious processes

# 2. ANALYSIS
🔐 quarr> Analyze auth.log last 48 hours, create timeline

# 3. CONTAINMENT
🔐 quarr> Block IP 185.220.101.34 in firewall

# 4. ERADICATION
🔐 quarr> Search persistence: cron jobs, services, hidden files

# 5. RECOVERY
🔐 quarr> Verify file integrity /usr/bin, compare baseline

# 6. DOCUMENTATION
🔐 quarr> technical
🔐 quarr> export
```

---

## 6. Scenario: Proactive Threat Hunting

### Situation: Hunting without specific alert/incident

```
🔐 quarr> Perform proactive threat hunting on this server.
            Search for compromise indicators, persistence, anomaly.

Agent automatically:

1. suspicious_files(/tmp, 7)            ← new files in temp?
2. suspicious_files(/dev/shm, 7)        ← executable in shared memory?
3. rootkit_scan()                        ← rootkit?
4. cron_audit()                          ← cron persistence?
5. service_audit()                       ← foreign service?
6. baseline_compare(/usr/bin)            ← binary changed?
7. dns_anomaly_check()                   ← DNS tunneling?
8. active_connections(suspicious)        ← C2 connections?
→ Report

🔐 quarr> YARA scan in /home /tmp /var

⚙️ yara_scan(directory=/home)
⚙️ yara_scan(directory=/tmp)

🔐 quarr> Search IOC from threat feed: domain evil-c2.com

⚙️ ioc_search(ioc_type=domain, value=evil-c2.com)
```

---

## 7. Scenario: Post-Incident Forensic

### Situation: Investigation after confirmed breach

```
# PRESERVE EVIDENCE
🔐 quarr> Hash all evidence files

⚙️ evidence_hash(filepath=/tmp/suspicious_binary)
⚙️ evidence_hash(filepath=/var/log/auth.log)

# MEMORY
🔐 quarr> Dump and analyze memory

⚙️ memory_dump(output_path=/evidence/memory.raw)
⚙️ memory_analysis(dump_path=/evidence/memory.raw, command=pslist)
⚙️ memory_analysis(dump_path=/evidence/memory.raw, command=netscan)
⚙️ memory_analysis(dump_path=/evidence/memory.raw, command=malfind)

# TIMELINE
🔐 quarr> Create timeline last 72 hours

⚙️ log_timeline(hours=72)

# FILE ANALYSIS
🔐 quarr> Analyze suspicious file

⚙️ metadata_extract(filepath=/tmp/.hidden_binary)
⚙️ string_extract(filepath=/tmp/.hidden_binary)
⚙️ binwalk_analysis(filepath=/tmp/.hidden_binary)

# NETWORK
🔐 quarr> Analyze captured PCAP

⚙️ pcap_analysis(pcap_file=/evidence/network.pcap)

# BROWSER
🔐 quarr> Extract browser history from compromised user

⚙️ browser_forensic(user=victim)

# DISK
🔐 quarr> Create forensic image and recover deleted files

⚙️ disk_image(source=/dev/sda1, destination=/evidence/disk.raw)
⚙️ file_recovery(image_path=/evidence/disk.raw)

# REPORT
🔐 quarr> technical
🔐 quarr> export
```

---

## 8. Knowledge Base

Agent (M5) automatically injects relevant knowledge when blue team/forensic context is detected:

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

---

## 9. Testing the Blue Team Scenarios

QUARR ships with automated tests that verify the blue-team detection logic and,
optionally, run the real tools against a host you control. There are three tiers.

### Tier 1 — Scenario tests (mocked, run by default)

`tests/test_blue_team_scenarios.py` exercises full incident-response scenarios
end-to-end with the subprocess layer mocked, so nothing touches the real system.
Detection/parsing is verified deterministically (a captured `auth.log` fixture
is used for the brute-force case).

```bash
python3 -m pytest tests/test_blue_team_scenarios.py -v
```

**Scenario A — SSH brute-force response (T1110 / T1078)**

| Step | Tool | Assertion |
|------|------|-----------|
| Detect | `log_analysis(auth, filter="Failed")` | attacker IP repeats ≥ 5× |
| Correlate | `active_connections(established)` | attacker session on :22 |
| Contain | `firewall_block(<IP>)` | `✅ Blocked`; **rejects** injection/hostnames |
| Recover | `firewall_unblock(<IP>)` | `✅ Unblocked` |

**Scenario B — Malware / C2 / persistence (T1059 / T1071 / T1053 / T1070)**

| Step | Tool | Assertion |
|------|------|-----------|
| Processes | `process_monitor()` | flags `nc -e`, `xmrig`; clean host = no flag |
| C2 beacon | `active_connections(suspicious)` | flags port 4444 |
| Backdoor | `port_audit()` | flags listening :4444 |
| Persistence | `cron_audit()` | surfaces malicious cron |
| Integrity | `file_integrity_check(/usr/bin, 7)` | reports modified binary; rejects path traversal |

There is also an **end-to-end agent test** that drives the brute-force playbook
through the real agent loop (LLM scripted, tool handlers patched), confirming the
policy allows LOW/MEDIUM blue tools for the `operator` role and that both tool
executions are recorded in state.

### Tier 2 — Live read-only (opt-in)

`tests/test_live_blue_team.py` runs the **actual** commands (`ss`, `ps`,
`systemctl`, `who`, `find`, ...) against the local host and asserts each tool
produces well-formed output without crashing. These are marked `@pytest.mark.live`
and skipped by default.

```bash
export QUARR_LIVE_BLUE=1
python3 -m pytest tests/test_live_blue_team.py -m live -v
```

### Tier 3 — Live state-changing (double opt-in, needs root)

The `firewall_block` / `firewall_unblock` tests modify `iptables`, so they are
gated behind a **second** opt-in. They operate on an RFC 5737 TEST-NET IP
(`203.0.113.42`, non-routable) and always clean up the rule afterward.

```bash
export QUARR_LIVE_BLUE=1
export QUARR_LIVE_BLUE_MUTATE=1   # only if you accept iptables changes
sudo -E python3 -m pytest tests/test_live_blue_team.py -m live -v
```

> ⚠️ **Authorization:** Only run live harnesses against systems you own or are
> explicitly authorized to test. A per-test timeout keeps a stalled command from
> hanging the suite.
