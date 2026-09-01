# PANDUAN M8 — Mobile Application Pentest

QUARR Agent sekarang memiliki **11 tools khusus mobile** yang terbagi menjadi:

- **Static Analysis** (5 tools) — Analisis APK tanpa device
- **Dynamic Analysis** (6 tools) — Testing di device via ADB/Frida

Total tools agent: **32** (21 web/network + 11 mobile).

---

## Daftar Isi

1. [Prasyarat Mobile](#1-prasyarat-mobile)
2. [Tools Mobile](#2-tools-mobile)
3. [Static Analysis — APK Pentest Tanpa Device](#3-static-analysis--apk-pentest-tanpa-device)
4. [Dynamic Analysis — Testing di Device](#4-dynamic-analysis--testing-di-device)
5. [Alur Otomatis](#5-alur-otomatis)
6. [Contoh Sesi Lengkap](#6-contoh-sesi-lengkap)
7. [OWASP Mobile Top 10 Mapping](#7-owasp-mobile-top-10-mapping)

---

## 1. Prasyarat Mobile

### Static Analysis (tanpa device)

| Tool | Fungsi | Cek | Install |
|------|--------|-----|---------|
| apktool | Decompile APK (resources) | `apktool --version` | `apt install apktool` |
| jadx | Decompile APK (Java source) | `jadx --version` | `apt install jadx` |
| keytool | Analisis certificate | `keytool` | Sudah ada di Java |
| apksigner | Verifikasi APK signing | `apksigner --version` | `apt install apksigner` |

### Dynamic Analysis (perlu device/emulator)

| Tool | Fungsi | Cek | Install |
|------|--------|-----|---------|
| adb | Android Debug Bridge | `adb version` | `apt install adb` |
| frida | Runtime instrumentation | `frida --version` | `pip install frida-tools` |
| objection | Mobile exploration | `objection version` | `pip install objection` |

### Device Setup (untuk dynamic analysis)

```bash
# Cek device terhubung
adb devices

# Untuk Frida: push frida-server ke device (perlu root)
adb push frida-server-android-arm64 /data/local/tmp/frida-server
adb shell su -c "chmod +x /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

> Static analysis **tidak memerlukan device** — cukup file APK.

---

## 2. Tools Mobile

### Static Analysis (5 tools)

| Tool | Kali Tool | Fungsi |
|------|-----------|--------|
| `apk_decompile` | apktool + jadx | Decompile APK → resources/smali + Java source |
| `apk_secrets_scan` | grep patterns | Cari hardcoded API keys, passwords, tokens, Firebase, AWS credentials, API endpoint URLs |
| `apk_manifest_analysis` | custom parser | Analisis AndroidManifest.xml: permissions, exported components, backup, debuggable, deeplinks, SDK |
| `apk_network_config` | custom parser | Analisis network_security_config.xml: cleartext, pinning, trust anchors, debug overrides |
| `apk_cert_check` | apksigner/keytool | Cek signing certificate: debug vs release, algorithm strength, V1/V2/V3 signing |

### Dynamic Analysis (6 tools)

| Tool | Kali Tool | Fungsi | Perlu |
|------|-----------|--------|-------|
| `adb_device_check` | adb | Cek device/emulator terhubung | ADB |
| `adb_app_info` | adb dumpsys | Info app: version, permissions, data dir | ADB |
| `adb_storage_check` | adb shell | Cek plaintext di SharedPreferences, SQLite, external storage | ADB + root |
| `adb_logcat_check` | adb logcat | Cek sensitive data di logs (credentials, tokens, PII) | ADB |
| `frida_ssl_bypass` | frida | Bypass SSL certificate pinning | Frida server |
| `objection_explore` | objection | Mobile exploration: env, SSL disable, root disable, hooking | Frida server |

---

## 3. Static Analysis — APK Pentest Tanpa Device

### Persiapan

Letakkan file APK di Kali:

```bash
# Dari device (jika terhubung)
adb shell pm path com.example.app
adb pull /data/app/com.example.app/base.apk /tmp/app.apk

# Atau download dari sumber lain
cp ~/Downloads/app-release.apk /tmp/app.apk
```

### Full Auto

```
🔐 quarr> Analisis keamanan APK di /tmp/app.apk
```

Agent otomatis menjalankan:

```
apk_decompile              ← decompile via apktool + jadx
    ▼
apk_manifest_analysis      ← permissions, exported, backup, debuggable
    ▼
apk_network_config         ← cleartext traffic, certificate pinning
    ▼
apk_cert_check             ← debug cert? weak algorithm?
    ▼
apk_secrets_scan           ← API keys, passwords, tokens, endpoints
    ▼
Laporan + Findings (auto-validated)
```

### Step-by-Step

```
🔐 quarr> Decompile APK /tmp/app.apk

⚙️ apk_decompile({"apk_path": "/tmp/app.apk"})
→ apktool: /tmp/quarr_apk/apktool (250 files)
→ jadx: /tmp/quarr_apk/jadx (180 files)

🔐 quarr> Analisis AndroidManifest.xml di /tmp/quarr_apk/apktool

⚙️ apk_manifest_analysis({"apk_decoded_dir": "/tmp/quarr_apk/apktool"})
→ [CRITICAL] debuggable=true
→ [HIGH] allowBackup=true
→ [MEDIUM] 3 exported activities
→ [MEDIUM] Custom deeplink: myapp://

🔐 quarr> Scan hardcoded secrets di /tmp/quarr_apk/jadx

⚙️ apk_secrets_scan({"directory": "/tmp/quarr_apk/jadx"})
→ 5 secrets found (API key, Firebase config, JWT)
→ 8 API endpoints found (api.example.com)

🔐 quarr> Cek konfigurasi network security

⚙️ apk_network_config({"apk_decoded_dir": "/tmp/quarr_apk/apktool"})
→ [HIGH] No certificate pinning
→ [HIGH] Cleartext traffic allowed

🔐 quarr> Cek signing certificate APK

⚙️ apk_cert_check({"apk_path": "/tmp/app.apk"})
→ [CRITICAL] Signed with DEBUG certificate
→ [MEDIUM] Only V1 signing (vulnerable to Janus)

🔐 quarr> findings
🔐 quarr> technical
```

### Setelah Static Analysis

API endpoints yang ditemukan di source code bisa langsung ditest:

```
🔐 quarr> Dari secrets scan, ditemukan API endpoint https://api.example.com.
            Test vulnerability di API tersebut.
```

Agent akan jalankan web pentest pipeline pada API endpoint.

---

## 4. Dynamic Analysis — Testing di Device

### Persiapan

```
🔐 quarr> Cek apakah ada device terhubung

⚙️ adb_device_check()
→ List of devices attached
→ emulator-5554  device
```

### App Info

```
🔐 quarr> Info lengkap tentang app com.example.banking

⚙️ adb_app_info({"package": "com.example.banking"})
→ Version: 3.2.1
→ targetSdk: 33
→ dataDir: /data/data/com.example.banking
→ Permissions: CAMERA, FINE_LOCATION, READ_CONTACTS
```

### Storage Check (perlu root)

```
🔐 quarr> Cek insecure data storage di com.example.banking

⚙️ adb_storage_check({"package": "com.example.banking"})
→ SENSITIVE DATA IN SharedPreferences:
→   <string name="auth_token">eyJhbGci...</string>
→   <string name="user_pin">123456</string>
→ DATABASES:
→   transactions.db (tables: users, transfers, logs)
→ EXTERNAL STORAGE:
→   profile_photo.jpg, cache/
```

### Logcat Check

```
🔐 quarr> Cek sensitive data di logcat com.example.banking

⚙️ adb_logcat_check({"package": "com.example.banking"})
→ ⚠️ SENSITIVE DATA IN LOGS:
→   password=user123
→   Bearer eyJhbGci...
→   user@example.com
```

### SSL Pinning Bypass

```
🔐 quarr> Bypass SSL pinning di com.example.banking

⚙️ frida_ssl_bypass({"package": "com.example.banking"})
→ [QUARR] SSL pinning bypassed
→ Sekarang traffic bisa di-intercept via Burp/mitmproxy
```

### Objection Exploration

```
🔐 quarr> Explore app com.example.banking via objection — cek environment

⚙️ objection_explore({"package": "com.example.banking", "command": "env"})
→ Application directory, cache, databases paths

🔐 quarr> Disable root detection di com.example.banking

⚙️ objection_explore({"package": "com.example.banking", "command": "android root disable"})
```

---

## 5. Alur Otomatis

### APK Analysis (tanpa device)

```
🔐 quarr> Pentest mobile APK di /tmp/banking.apk
```

```
apk_decompile                    apktool + jadx
    ▼
apk_manifest_analysis            permissions, exported, backup, debug
    ▼
apk_network_config               cleartext, pinning
    ▼
apk_cert_check                   debug cert, signing scheme
    ▼
apk_secrets_scan                 API keys, tokens, endpoints
    ▼
[Jika API endpoints ditemukan]
    ▼
vulnerability_scan               nuclei pada API endpoints
    ▼
sqli_scan                        SQLi pada API endpoints
    ▼
Laporan + Findings
```

### Device Analysis (dengan ADB)

```
🔐 quarr> Pentest app com.example.banking di device
```

```
adb_device_check                 device terhubung?
    ▼
adb_app_info                     version, permissions, flags
    ▼
adb_storage_check                SharedPreferences, SQLite, external
    ▼
adb_logcat_check                 sensitive data di logs
    ▼
frida_ssl_bypass                 bypass certificate pinning
    ▼
Laporan + Findings
```

### Full Mobile Pentest (APK + Device)

```
🔐 quarr> Full mobile pentest: APK /tmp/banking.apk, package com.example.banking
```

Agent menjalankan semua static analysis dulu, lalu dynamic analysis.

---

## 6. Contoh Sesi Lengkap

```
$ python3 main.py

📋 ENGAGEMENT SETUP
Assessment name: Banking App Mobile Pentest
  + target: api.bankapp.com
  + target:
  - exclude:

🤖 Backend: OpenAI
   Model: gpt-4o-mini

🔐 quarr> Lakukan full mobile pentest pada APK /tmp/bankapp.apk

🧠 Agent thinking...
⚙️ Step 1: apk_decompile({"apk_path": "/tmp/bankapp.apk"})
⚙️ Step 2: apk_manifest_analysis({"apk_decoded_dir": "/tmp/quarr_apk/apktool"})
⚙️ Step 3: apk_network_config({"apk_decoded_dir": "/tmp/quarr_apk/apktool"})
⚙️ Step 4: apk_cert_check({"apk_path": "/tmp/bankapp.apk"})
⚙️ Step 5: apk_secrets_scan({"directory": "/tmp/quarr_apk/jadx"})

[FINDING VALIDATION] FIND-abc: detected → confirmed

────────────────────────────────────────────────────────────
## Mobile Security Assessment — bankapp.apk

### Static Analysis Findings

1. [CRITICAL] android:debuggable="true" (CONFIRMED)
   App can be debugged in production
   CWE-489 | Remediation: Set debuggable=false

2. [HIGH] android:allowBackup="true" (CONFIRMED)
   Data extractable via adb backup
   CWE-921 | Remediation: Set allowBackup=false

3. [HIGH] No certificate pinning (DETECTED)
   Traffic interceptable with proxy certificate
   CWE-295 | Remediation: Implement cert pinning

4. [HIGH] Hardcoded API key (DETECTED)
   BuildConfig.java: API_KEY = "sk-live-xxx..."
   CWE-798 | Remediation: Move to secure storage

5. [MEDIUM] 3 exported activities (DETECTED)
   Potential for deeplink hijacking

### API Endpoints Found
   https://api.bankapp.com/v1/auth
   https://api.bankapp.com/v1/transfer
   https://api.bankapp.com/v1/accounts

### Recommendations
1. Remove debuggable flag immediately
2. Implement certificate pinning
3. Move credentials to Android Keystore
4. Restrict exported components
────────────────────────────────────────────────────────────

🔐 quarr> Sekarang test API endpoint yang ditemukan

⚙️ Step 6: service_enumeration({"target": "api.bankapp.com", "profile": "basic"})
⚙️ Step 7: vulnerability_scan({"target": "api.bankapp.com", "severity": "critical,high"})
...

🔐 quarr> findings
🔐 quarr> technical
✅ Technical report exported: report_technical_20260830_080000.md

🔐 quarr> export
✅ Findings exported: findings_20260830_080000.json
```

---

## 7. OWASP Mobile Top 10 Mapping

Agent (M5 RAG) otomatis inject OWASP Mobile Top 10 knowledge saat mendeteksi konteks mobile.

| OWASP | Tool yang Digunakan | Auto? |
|-------|---------------------|-------|
| M1 Improper Credential Usage | `apk_secrets_scan`, `adb_storage_check` | ✅ |
| M2 Supply Chain Security | `apk_decompile` (dependency check) | ⚠️ Partial |
| M3 Insecure Auth | `bruteforce_login`, `sqli_scan` | ✅ |
| M4 Input Validation | `sqli_scan`, `xss_scan`, `command_injection_scan` | ✅ |
| M5 Insecure Communication | `apk_network_config`, `frida_ssl_bypass`, `ssl_scan` | ✅ |
| M6 Privacy Controls | `adb_logcat_check`, `adb_storage_check`, `apk_manifest_analysis` | ✅ |
| M7 Binary Protections | `apk_decompile`, `objection_explore` | ✅ |
| M8 Security Misconfiguration | `apk_manifest_analysis`, `apk_cert_check` | ✅ |
| M9 Insecure Data Storage | `adb_storage_check`, `adb_logcat_check`, `apk_secrets_scan` | ✅ |
| M10 Insufficient Cryptography | `apk_secrets_scan`, `apk_decompile` | ⚠️ Partial |

Saat agent menemukan konteks mobile, knowledge seperti berikut otomatis di-inject:

```
RELEVANT SECURITY KNOWLEDGE:
[M1:2024] Improper Credential Usage: Hardcoded credentials, insecure credential storage...
  Test: Decompile APK → search for hardcoded API keys, passwords, tokens.
[M5:2024] Insecure Communication: Missing or broken SSL/TLS, no certificate pinning...
  Test: Check network_security_config.xml. Test certificate pinning bypass.
[M8:2024] Security Misconfiguration: Debug mode enabled, allowBackup, exported components...
  Test: Analyze AndroidManifest.xml for misconfigurations.
[M9:2024] Insecure Data Storage: Sensitive data stored in plaintext...
  Test: Check all storage locations for plaintext secrets.
```
