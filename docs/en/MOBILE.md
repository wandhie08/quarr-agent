# M8 GUIDE — Mobile Application Pentest

QUARR Agent now has **11 mobile-specific tools** divided into:

- **Static Analysis** (5 tools) — APK analysis without device
- **Dynamic Analysis** (6 tools) — Testing on device via ADB/Frida

Total agent tools: **32** (21 web/network + 11 mobile).

---

## Table of Contents

1. [Mobile Prerequisites](#1-mobile-prerequisites)
2. [Mobile Tools](#2-mobile-tools)
3. [Static Analysis — APK Pentest Without Device](#3-static-analysis--apk-pentest-without-device)
4. [Dynamic Analysis — Testing on Device](#4-dynamic-analysis--testing-on-device)
5. [Automated Flow](#5-automated-flow)
6. [Complete Session Example](#6-complete-session-example)
7. [OWASP Mobile Top 10 Mapping](#7-owasp-mobile-top-10-mapping)

---

## 1. Mobile Prerequisites

### Static Analysis (without device)

| Tool | Function | Check | Install |
|------|----------|-------|---------|
| apktool | Decompile APK (resources) | `apktool --version` | `apt install apktool` |
| jadx | Decompile APK (Java source) | `jadx --version` | `apt install jadx` |
| keytool | Certificate analysis | `keytool` | Already in Java |
| apksigner | Verify APK signing | `apksigner --version` | `apt install apksigner` |

### Dynamic Analysis (requires device/emulator)

| Tool | Function | Check | Install |
|------|----------|-------|---------|
| adb | Android Debug Bridge | `adb version` | `apt install adb` |
| frida | Runtime instrumentation | `frida --version` | `pip install frida-tools` |
| objection | Mobile exploration | `objection version` | `pip install objection` |

### Device Setup (for dynamic analysis)

```bash
# Check connected device
adb devices

# For Frida: push frida-server to device (requires root)
adb push frida-server-android-arm64 /data/local/tmp/frida-server
adb shell su -c "chmod +x /data/local/tmp/frida-server"
adb shell su -c "/data/local/tmp/frida-server &"
```

> Static analysis **does not require a device** — only the APK file.

---

## 2. Mobile Tools

### Static Analysis (5 tools)

| Tool | Kali Tool | Function |
|------|-----------|----------|
| `apk_decompile` | apktool + jadx | Decompile APK → resources/smali + Java source |
| `apk_secrets_scan` | grep patterns | Search hardcoded API keys, passwords, tokens, Firebase, AWS credentials, API endpoint URLs |
| `apk_manifest_analysis` | custom parser | Analyze AndroidManifest.xml: permissions, exported components, backup, debuggable, deeplinks, SDK |
| `apk_network_config` | custom parser | Analyze network_security_config.xml: cleartext, pinning, trust anchors, debug overrides |
| `apk_cert_check` | apksigner/keytool | Check signing certificate: debug vs release, algorithm strength, V1/V2/V3 signing |

### Dynamic Analysis (6 tools)

| Tool | Kali Tool | Function | Requires |
|------|-----------|----------|----------|
| `adb_device_check` | adb | Check device/emulator connected | ADB |
| `adb_app_info` | adb dumpsys | App info: version, permissions, data dir | ADB |
| `adb_storage_check` | adb shell | Check plaintext in SharedPreferences, SQLite, external storage | ADB + root |
| `adb_logcat_check` | adb logcat | Check sensitive data in logs (credentials, tokens, PII) | ADB |
| `frida_ssl_bypass` | frida | Bypass SSL certificate pinning | Frida server |
| `objection_explore` | objection | Mobile exploration: env, SSL disable, root disable, hooking | Frida server |

---

## 3. Static Analysis — APK Pentest Without Device

### Preparation

Place APK file in Kali:

```bash
# From device (if connected)
adb shell pm path com.example.app
adb pull /data/app/com.example.app/base.apk /tmp/app.apk

# Or download from other source
cp ~/Downloads/app-release.apk /tmp/app.apk
```

### Full Auto

```
🔐 quarr> Analyze APK security at /tmp/app.apk
```

Agent automatically runs:

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
Report + Findings (auto-validated)
```

### Step-by-Step

```
🔐 quarr> Decompile APK /tmp/app.apk

⚙️ apk_decompile({"apk_path": "/tmp/app.apk"})
→ apktool: /tmp/quarr_apk/apktool (250 files)
→ jadx: /tmp/quarr_apk/jadx (180 files)

🔐 quarr> Analyze AndroidManifest.xml at /tmp/quarr_apk/apktool

⚙️ apk_manifest_analysis({"apk_decoded_dir": "/tmp/quarr_apk/apktool"})
→ [CRITICAL] debuggable=true
→ [HIGH] allowBackup=true
→ [MEDIUM] 3 exported activities
→ [MEDIUM] Custom deeplink: myapp://

🔐 quarr> Scan hardcoded secrets at /tmp/quarr_apk/jadx

⚙️ apk_secrets_scan({"directory": "/tmp/quarr_apk/jadx"})
→ 5 secrets found (API key, Firebase config, JWT)
→ 8 API endpoints found (api.example.com)

🔐 quarr> Check network security config

⚙️ apk_network_config({"apk_decoded_dir": "/tmp/quarr_apk/apktool"})
→ [HIGH] No certificate pinning
→ [HIGH] Cleartext traffic allowed

🔐 quarr> Check APK signing certificate

⚙️ apk_cert_check({"apk_path": "/tmp/app.apk"})
→ [CRITICAL] Signed with DEBUG certificate
→ [MEDIUM] Only V1 signing (vulnerable to Janus)

🔐 quarr> findings
🔐 quarr> technical
```

### After Static Analysis

API endpoints found in source code can be directly tested:

```
🔐 quarr> From secrets scan, found API endpoint https://api.example.com.
            Test vulnerabilities on that API.
```

Agent will run web pentest pipeline on API endpoint.

---

## 4. Dynamic Analysis — Testing on Device

### Preparation

```
🔐 quarr> Check if device is connected

⚙️ adb_device_check()
→ List of devices attached
→ emulator-5554  device
```

### App Info

```
🔐 quarr> Full info about app com.example.banking

⚙️ adb_app_info({"package": "com.example.banking"})
→ Version: 3.2.1
→ targetSdk: 33
→ dataDir: /data/data/com.example.banking
→ Permissions: CAMERA, FINE_LOCATION, READ_CONTACTS
```

### Storage Check (requires root)

```
🔐 quarr> Check insecure data storage in com.example.banking

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
🔐 quarr> Check sensitive data in logcat com.example.banking

⚙️ adb_logcat_check({"package": "com.example.banking"})
→ ⚠️ SENSITIVE DATA IN LOGS:
→   password=user123
→   Bearer eyJhbGci...
→   user@example.com
```

### SSL Pinning Bypass

```
🔐 quarr> Bypass SSL pinning in com.example.banking

⚙️ frida_ssl_bypass({"package": "com.example.banking"})
→ [QUARR] SSL pinning bypassed
→ Now traffic can be intercepted via Burp/mitmproxy
```

### Objection Exploration

```
🔐 quarr> Explore app com.example.banking via objection — check environment

⚙️ objection_explore({"package": "com.example.banking", "command": "env"})
→ Application directory, cache, databases paths

🔐 quarr> Disable root detection in com.example.banking

⚙️ objection_explore({"package": "com.example.banking", "command": "android root disable"})
```

---

## 5. Automated Flow

### APK Analysis (without device)

```
🔐 quarr> Mobile APK pentest at /tmp/banking.apk
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
[If API endpoints found]
    ▼
vulnerability_scan               nuclei on API endpoints
    ▼
sqli_scan                        SQLi on API endpoints
    ▼
Report + Findings
```

### Device Analysis (with ADB)

```
🔐 quarr> Pentest app com.example.banking on device
```

```
adb_device_check                 device connected?
    ▼
adb_app_info                     version, permissions, flags
    ▼
adb_storage_check                SharedPreferences, SQLite, external
    ▼
adb_logcat_check                 sensitive data in logs
    ▼
frida_ssl_bypass                 bypass certificate pinning
    ▼
Report + Findings
```

### Full Mobile Pentest (APK + Device)

```
🔐 quarr> Full mobile pentest: APK /tmp/banking.apk, package com.example.banking
```

Agent runs all static analysis first, then dynamic analysis.

---

## 6. Complete Session Example

```
$ python3 main.py

📋 ENGAGEMENT SETUP
Assessment name: Banking App Mobile Pentest
  + target: api.bankapp.com
  + target:
  - exclude:

🤖 Backend: OpenAI
   Model: gpt-4o-mini

🔐 quarr> Perform full mobile pentest on APK /tmp/bankapp.apk

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

🔐 quarr> Now test the API endpoints found

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

Agent (M5 RAG) automatically injects OWASP Mobile Top 10 knowledge when mobile context is detected.

| OWASP | Tools Used | Auto? |
|-------|------------|-------|
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

When agent detects mobile context, knowledge like the following is automatically injected:

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
