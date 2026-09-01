"""
mobile_tools.py - M8: Mobile Application Pentest Tools

Tools untuk analisis keamanan aplikasi mobile (Android & iOS).

Dibagi menjadi 3 kategori:
1. Static Analysis — APK decompile, secret scan, manifest analysis (tanpa device)
2. Dynamic Analysis — ADB, Frida, Objection (perlu device/emulator)
3. API Extraction — Temukan & test API endpoints dari source code

Semua tool mengikuti arsitektur V1:
- LLM memilih tool + parameter
- Tool executor menentukan command
- Output di-parse ke structured JSON
- Policy engine memvalidasi scope
"""

import subprocess
import shlex
import re
import os
import json
from typing import Dict, Any


# ============================================================
# Utility
# ============================================================

def _run_cmd(cmd: str, timeout: int = 120) -> str:
    try:
        result = subprocess.run(
            shlex.split(cmd), capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR] {result.stderr}"
        return output if output.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command timed out after {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] Command not found: {cmd.split()[0]}"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def _run_shell(cmd: str, timeout: int = 60) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[STDERR] {result.stderr}"
        return output if output.strip() else "[No output]"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command timed out after {timeout}s"
    except Exception as e:
        return f"[ERROR] {str(e)}"


def _validate_path(path: str) -> str:
    path = path.strip()
    if not path:
        raise ValueError("Path cannot be empty")
    if ".." in path or path.startswith("/etc") or path.startswith("/root"):
        raise ValueError(f"Path not allowed: {path}")
    return path


# ============================================================
# STATIC ANALYSIS (Tanpa device)
# ============================================================

def apk_decompile(apk_path: str, output_dir: str = "/tmp/quarr_apk") -> str:
    """
    Decompile APK menggunakan apktool (resources + smali) dan
    jadx (Java source code). Dua-duanya sekaligus.
    """
    apk_path = _validate_path(apk_path)
    output_dir = _validate_path(output_dir)

    apktool_dir = f"{output_dir}/apktool"
    jadx_dir = f"{output_dir}/jadx"

    results = []

    # apktool — resources, smali, manifest
    cmd = f"apktool d {shlex.quote(apk_path)} -o {shlex.quote(apktool_dir)} -f"
    out = _run_cmd(cmd, timeout=120)
    if os.path.exists(apktool_dir):
        file_count = sum(len(files) for _, _, files in os.walk(apktool_dir))
        results.append(f"[apktool] Decoded to {apktool_dir} ({file_count} files)")
    else:
        results.append(f"[apktool] Failed: {out[:200]}")

    # jadx — Java source
    cmd = f"jadx -d {shlex.quote(jadx_dir)} {shlex.quote(apk_path)} --no-res"
    out = _run_cmd(cmd, timeout=180)
    if os.path.exists(jadx_dir):
        file_count = sum(len(files) for _, _, files in os.walk(jadx_dir))
        results.append(f"[jadx] Decompiled to {jadx_dir} ({file_count} files)")
    else:
        results.append(f"[jadx] Failed: {out[:200]}")

    return "\n".join(results)


def apk_secrets_scan(directory: str) -> str:
    """
    Scan source code untuk hardcoded secrets:
    API keys, passwords, tokens, private keys, Firebase configs,
    AWS credentials, database connection strings.
    """
    directory = _validate_path(directory)

    patterns = {
        "API Key": r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([^"\']{10,})["\']',
        "Secret Key": r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([^"\']{10,})["\']',
        "Password": r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})["\']',
        "Token": r'(?:auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*["\']([^"\']{10,})["\']',
        "Private Key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        "AWS Key": r'AKIA[0-9A-Z]{16}',
        "Firebase": r'AIza[0-9A-Za-z_-]{35}',
        "Google OAuth": r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        "JWT": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.',
        "Base64 High Entropy": r'(?:secret|key|token|password)\s*=\s*["\'][A-Za-z0-9+/=]{32,}["\']',
    }

    combined_pattern = "|".join(f"({p})" for p in patterns.values())

    cmd = (
        f"grep -rnI --include='*.java' --include='*.kt' --include='*.xml' "
        f"--include='*.json' --include='*.properties' --include='*.yml' "
        f"--include='*.gradle' --include='*.smali' "
        f"-E '{combined_pattern}' {shlex.quote(directory)}"
    )

    output = _run_shell(cmd, timeout=30)

    # Also check for URLs (API endpoints)
    url_cmd = (
        f"grep -rnoI --include='*.java' --include='*.kt' --include='*.xml' "
        f"--include='*.json' --include='*.smali' "
        f"-E 'https?://[a-zA-Z0-9._/-]+' {shlex.quote(directory)} | "
        f"grep -v 'schemas.android.com\\|schemas.microsoft.com\\|www.w3.org\\|"
        f"xmlns\\|apache.org\\|google.com/schemas\\|github.com' | head -50"
    )
    url_output = _run_shell(url_cmd, timeout=15)

    result = ""
    if output and "[No output]" not in output:
        result += f"=== SECRETS FOUND ===\n{output}\n"
    else:
        result += "=== SECRETS: None found ===\n"

    if url_output and "[No output]" not in url_output:
        result += f"\n=== API ENDPOINTS IN SOURCE ===\n{url_output}\n"
    else:
        result += "\n=== API ENDPOINTS: None found ===\n"

    return result


def apk_manifest_analysis(apk_decoded_dir: str) -> str:
    """
    Deep analysis AndroidManifest.xml:
    - Permissions (dangerous ones)
    - Exported components (activities, services, receivers, providers)
    - Backup/debuggable flags
    - Network security config
    - Intent filters (deeplinks)
    - Min/target SDK
    """
    apk_decoded_dir = _validate_path(apk_decoded_dir)
    manifest_path = os.path.join(apk_decoded_dir, "AndroidManifest.xml")

    if not os.path.exists(manifest_path):
        # Try apktool subdirectory
        alt = os.path.join(apk_decoded_dir, "apktool", "AndroidManifest.xml")
        if os.path.exists(alt):
            manifest_path = alt
        else:
            return f"[ERROR] AndroidManifest.xml not found in {apk_decoded_dir}"

    try:
        with open(manifest_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return f"[ERROR] Cannot read manifest: {e}"

    findings = []
    info = []

    # Package name
    pkg = re.search(r'package="([^"]+)"', content)
    if pkg:
        info.append(f"Package: {pkg.group(1)}")

    # SDK versions
    min_sdk = re.search(r'android:minSdkVersion="(\d+)"', content)
    target_sdk = re.search(r'android:targetSdkVersion="(\d+)"', content)
    if min_sdk:
        sdk_ver = int(min_sdk.group(1))
        info.append(f"minSdkVersion: {sdk_ver}")
        if sdk_ver < 24:
            findings.append(f"[MEDIUM] minSdkVersion={sdk_ver} (< 24, Android 7). Older devices may lack security features.")
    if target_sdk:
        info.append(f"targetSdkVersion: {target_sdk.group(1)}")

    # Dangerous flags
    if 'android:allowBackup="true"' in content:
        findings.append("[HIGH] android:allowBackup=\"true\" — App data can be extracted via adb backup without root.")
    if 'android:debuggable="true"' in content:
        findings.append("[CRITICAL] android:debuggable=\"true\" — App can be debugged in production. Full memory access possible.")
    if 'android:usesCleartextTraffic="true"' in content:
        findings.append("[HIGH] android:usesCleartextTraffic=\"true\" — HTTP cleartext traffic allowed. Credentials sent in plain text.")

    # Exported components
    exported_activities = re.findall(
        r'<activity[^>]*android:name="([^"]+)"[^>]*android:exported="true"', content
    )
    exported_services = re.findall(
        r'<service[^>]*android:name="([^"]+)"[^>]*android:exported="true"', content
    )
    exported_receivers = re.findall(
        r'<receiver[^>]*android:name="([^"]+)"[^>]*android:exported="true"', content
    )
    exported_providers = re.findall(
        r'<provider[^>]*android:name="([^"]+)"[^>]*android:exported="true"', content
    )

    if exported_activities:
        findings.append(f"[MEDIUM] {len(exported_activities)} exported activities: {', '.join(exported_activities[:5])}")
    if exported_services:
        findings.append(f"[MEDIUM] {len(exported_services)} exported services: {', '.join(exported_services[:5])}")
    if exported_receivers:
        findings.append(f"[LOW] {len(exported_receivers)} exported receivers: {', '.join(exported_receivers[:5])}")
    if exported_providers:
        findings.append(f"[HIGH] {len(exported_providers)} exported content providers: {', '.join(exported_providers[:5])} — potential data leak")

    # Deeplinks
    deeplinks = re.findall(r'android:scheme="([^"]+)"', content)
    deeplink_hosts = re.findall(r'android:host="([^"]+)"', content)
    if deeplinks:
        schemes = list(set(deeplinks) - {"http", "https"})
        if schemes:
            findings.append(f"[MEDIUM] Custom deeplink schemes: {', '.join(schemes)} — test for deeplink hijacking")
    if deeplink_hosts:
        info.append(f"Deeplink hosts: {', '.join(set(deeplink_hosts))}")

    # Dangerous permissions
    dangerous_perms = [
        "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS", "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION", "RECORD_AUDIO", "READ_PHONE_STATE",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "SEND_SMS",
        "READ_SMS", "CALL_PHONE", "READ_CALL_LOG",
    ]
    found_perms = []
    for perm in dangerous_perms:
        if perm in content:
            found_perms.append(perm)
    if found_perms:
        info.append(f"Dangerous permissions: {', '.join(found_perms)}")

    # Network security config
    if 'networkSecurityConfig' in content:
        info.append("Custom networkSecurityConfig defined")
    else:
        findings.append("[LOW] No custom networkSecurityConfig — using platform defaults")

    # Build output
    output = "=== APP INFO ===\n" + "\n".join(info) + "\n"
    if findings:
        output += f"\n=== FINDINGS ({len(findings)}) ===\n" + "\n".join(findings) + "\n"
    else:
        output += "\n=== FINDINGS: No issues found ===\n"

    return output


def apk_network_config(apk_decoded_dir: str) -> str:
    """
    Analisis network_security_config.xml:
    - Cleartext traffic domains
    - Custom trust anchors
    - Certificate pinning configuration
    - Debug overrides
    """
    apk_decoded_dir = _validate_path(apk_decoded_dir)

    # Search for network security config
    search_paths = [
        os.path.join(apk_decoded_dir, "res", "xml", "network_security_config.xml"),
        os.path.join(apk_decoded_dir, "apktool", "res", "xml", "network_security_config.xml"),
    ]

    config_path = None
    for p in search_paths:
        if os.path.exists(p):
            config_path = p
            break

    if not config_path:
        # Try find
        find_cmd = f"find {shlex.quote(apk_decoded_dir)} -name 'network_security_config.xml' -type f 2>/dev/null"
        result = _run_shell(find_cmd, timeout=5)
        if result.strip() and "[" not in result:
            config_path = result.strip().split("\n")[0]

    if not config_path:
        return "[INFO] No network_security_config.xml found. App uses platform defaults."

    try:
        with open(config_path, 'r') as f:
            content = f.read()
    except Exception as e:
        return f"[ERROR] Cannot read config: {e}"

    findings = []

    if 'cleartextTrafficPermitted="true"' in content:
        domains = re.findall(r'<domain[^>]*>([^<]+)</domain>', content)
        findings.append(f"[HIGH] Cleartext traffic allowed for: {', '.join(domains) if domains else 'all domains'}")

    if '<trust-anchors>' in content:
        if 'user' in content:
            findings.append("[MEDIUM] User-installed certificates trusted — easy to intercept with proxy")
        if 'system' in content:
            findings.append("[INFO] System certificates trusted (normal)")

    if '<pin-set' in content:
        pins = re.findall(r'<pin\s+digest="([^"]+)">([^<]+)</pin>', content)
        findings.append(f"[INFO] Certificate pinning configured: {len(pins)} pin(s)")
        for alg, pin in pins[:3]:
            findings.append(f"  Pin: {alg} = {pin[:20]}...")
    else:
        findings.append("[HIGH] No certificate pinning configured — traffic can be intercepted with proxy cert")

    if '<debug-overrides>' in content:
        findings.append("[MEDIUM] Debug overrides present — may weaken security in debug builds")

    output = f"=== NETWORK SECURITY CONFIG ===\nFile: {config_path}\n\n"
    output += "\n".join(findings) if findings else "No issues found"
    return output


def apk_cert_check(apk_path: str) -> str:
    """
    Analisis APK signing certificate:
    - Debug vs release certificate
    - Signature algorithm strength
    - Certificate validity
    - V1/V2/V3 signing scheme
    """
    apk_path = _validate_path(apk_path)

    results = []

    # apksigner verify
    cmd = f"apksigner verify --verbose --print-certs {shlex.quote(apk_path)}"
    out = _run_cmd(cmd, timeout=15)
    if "[ERROR]" not in out:
        results.append(f"=== APK SIGNATURE ===\n{out}")
    else:
        # Fallback: keytool + jarsigner
        cmd = f"jarsigner -verify -verbose -certs {shlex.quote(apk_path)} 2>&1 | head -30"
        out = _run_shell(cmd, timeout=15)
        results.append(f"=== JAR SIGNATURE ===\n{out}")

    # Check for debug cert indicators
    combined = "\n".join(results)
    findings = []

    if "CN=Android Debug" in combined or "debug" in combined.lower():
        findings.append("[CRITICAL] Signed with DEBUG certificate — not for production release")
    if "MD5withRSA" in combined or "SHA1withRSA" in combined:
        findings.append("[MEDIUM] Weak signature algorithm (MD5/SHA1) — should use SHA256+")
    if "v1 scheme" in combined.lower() and "v2 scheme" not in combined.lower():
        findings.append("[MEDIUM] Only V1 signing — vulnerable to Janus (CVE-2017-13156). Should use V2/V3.")

    if findings:
        results.append("\n=== FINDINGS ===\n" + "\n".join(findings))

    return "\n".join(results)


# ============================================================
# DYNAMIC ANALYSIS (Perlu ADB / Device)
# ============================================================

def adb_device_check() -> str:
    """Cek apakah ada Android device/emulator yang terhubung via ADB."""
    return _run_cmd("adb devices -l", timeout=10)


def adb_app_info(package: str) -> str:
    """
    Ambil informasi lengkap tentang installed app:
    - Package info, version, permissions
    - Data directories
    - Signatures
    """
    package = package.strip()
    if not re.match(r'^[a-zA-Z0-9._]+$', package):
        return f"[ERROR] Invalid package name: {package}"

    results = []

    # Package info
    out = _run_cmd(f"adb shell dumpsys package {shlex.quote(package)}", timeout=10)
    if "[ERROR]" not in out:
        # Extract key info
        lines = out.split("\n")
        relevant = []
        for line in lines:
            line_s = line.strip()
            if any(k in line_s for k in [
                "versionName", "versionCode", "targetSdk", "minSdk",
                "dataDir", "flags=", "pkgFlags="
            ]):
                relevant.append(line_s)
        results.append("=== PACKAGE INFO ===\n" + "\n".join(relevant[:20]))

    # Granted permissions
    out = _run_cmd(f"adb shell dumpsys package {shlex.quote(package)} | grep 'granted=true'", timeout=10)
    if out.strip() and "[ERROR]" not in out:
        results.append(f"\n=== GRANTED PERMISSIONS ===\n{out[:2000]}")

    return "\n".join(results) if results else "[ERROR] Could not get app info. Is device connected?"


def adb_storage_check(package: str) -> str:
    """
    Cek insecure data storage di device:
    - SharedPreferences (plaintext secrets)
    - SQLite databases (unencrypted)
    - Cache files
    - External storage
    Memerlukan root atau debuggable app.
    """
    package = package.strip()
    if not re.match(r'^[a-zA-Z0-9._]+$', package):
        return f"[ERROR] Invalid package name: {package}"

    data_dir = f"/data/data/{package}"
    results = []

    # SharedPreferences
    cmd = f"adb shell su -c 'cat {data_dir}/shared_prefs/*.xml' 2>/dev/null"
    out = _run_shell(cmd, timeout=10)
    if out.strip() and "[ERROR]" not in out and "Permission denied" not in out:
        # Search for sensitive data
        sensitive_patterns = ["password", "token", "key", "secret", "pin", "auth", "session", "credential"]
        sensitive_lines = []
        for line in out.split("\n"):
            if any(p in line.lower() for p in sensitive_patterns):
                sensitive_lines.append(line.strip())
        if sensitive_lines:
            results.append("=== SENSITIVE DATA IN SharedPreferences ===\n" + "\n".join(sensitive_lines[:20]))
        else:
            results.append("=== SharedPreferences: No obvious sensitive data ===")
    else:
        # Try without root (run-as for debuggable apps)
        cmd = f"adb shell run-as {shlex.quote(package)} cat shared_prefs/*.xml 2>/dev/null"
        out = _run_shell(cmd, timeout=10)
        if out.strip() and "not debuggable" not in out.lower():
            results.append(f"=== SharedPreferences (via run-as) ===\n{out[:3000]}")
        else:
            results.append("[INFO] SharedPreferences not accessible (need root or debuggable app)")

    # SQLite databases
    cmd = f"adb shell su -c 'ls -la {data_dir}/databases/' 2>/dev/null"
    out = _run_shell(cmd, timeout=5)
    if out.strip() and "No such file" not in out:
        results.append(f"\n=== DATABASES ===\n{out}")
        # Try to read database tables
        db_files = re.findall(r'(\S+\.db)\s*$', out, re.MULTILINE)
        for db in db_files[:3]:
            tables_cmd = f"adb shell su -c 'sqlite3 {data_dir}/databases/{db} .tables' 2>/dev/null"
            tables = _run_shell(tables_cmd, timeout=5)
            if tables.strip():
                results.append(f"  Tables in {db}: {tables.strip()}")

    # External storage
    cmd = f"adb shell ls -la /sdcard/Android/data/{package}/ 2>/dev/null"
    out = _run_shell(cmd, timeout=5)
    if out.strip() and "No such file" not in out:
        results.append(f"\n=== EXTERNAL STORAGE ===\n{out}")

    return "\n".join(results) if results else "[INFO] No accessible storage found"


def adb_logcat_check(package: str) -> str:
    """
    Cek sensitive data di logcat:
    - Credentials, tokens, API keys dalam logs
    - PII (email, phone, name)
    - Debug information
    Capture 5 detik log.
    """
    package = package.strip()
    if not re.match(r'^[a-zA-Z0-9._]+$', package):
        return f"[ERROR] Invalid package name: {package}"

    # Clear logcat first, then capture
    _run_cmd("adb logcat -c", timeout=3)

    # Capture for package
    cmd = f"timeout 5 adb logcat --pid=$(adb shell pidof {shlex.quote(package)}) 2>/dev/null"
    out = _run_shell(cmd, timeout=10)

    if not out.strip() or "[ERROR]" in out:
        # Fallback: capture all and grep
        cmd = f"timeout 5 adb logcat -d 2>/dev/null | grep -i {shlex.quote(package)} | tail -100"
        out = _run_shell(cmd, timeout=10)

    if not out.strip():
        return "[INFO] No log output captured. Is the app running?"

    # Search for sensitive data
    sensitive_patterns = [
        r'password[=:]\s*\S+',
        r'token[=:]\s*\S+',
        r'Bearer\s+\S+',
        r'api[_-]?key[=:]\s*\S+',
        r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.',  # JWT
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # email
        r'\b08\d{8,11}\b',  # Indonesian phone
    ]

    findings = []
    for pattern in sensitive_patterns:
        matches = re.findall(pattern, out, re.IGNORECASE)
        if matches:
            findings.extend(matches[:3])

    result = f"=== LOGCAT ({len(out.splitlines())} lines captured) ===\n"
    if findings:
        result += f"\n⚠️ SENSITIVE DATA IN LOGS:\n" + "\n".join(f"  {f}" for f in findings[:10])
    else:
        result += "No obvious sensitive data in logs"

    return result


def frida_ssl_bypass(package: str) -> str:
    """
    Bypass SSL certificate pinning menggunakan Frida.
    Inject universal SSL pinning bypass script.
    """
    package = package.strip()
    if not re.match(r'^[a-zA-Z0-9._]+$', package):
        return f"[ERROR] Invalid package name: {package}"

    # Check frida-server
    check = _run_cmd("adb shell su -c 'pidof frida-server'", timeout=5)
    if "[ERROR]" in check or not check.strip():
        return (
            "[ERROR] frida-server not running on device.\n"
            "Start it with:\n"
            "  adb push frida-server /data/local/tmp/\n"
            "  adb shell su -c '/data/local/tmp/frida-server &'"
        )

    # Universal SSL bypass script
    bypass_script = """
Java.perform(function() {
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManagerImpl = Java.registerClass({
        name: 'QuarrTrustManager',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var TrustManagers = [TrustManagerImpl.$new()];
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, TrustManagers, null);
    send("[QUARR] SSL pinning bypassed");
});
"""

    script_path = "/tmp/quarr_ssl_bypass.js"
    with open(script_path, "w") as f:
        f.write(bypass_script)

    cmd = f"timeout 10 frida -U -f {shlex.quote(package)} -l {script_path} --no-pause 2>&1 | head -30"
    out = _run_shell(cmd, timeout=15)

    return f"=== SSL PINNING BYPASS ===\nTarget: {package}\n\n{out}"


def objection_explore(package: str, command: str = "env") -> str:
    """
    Frida-based mobile exploration via Objection.

    Commands:
    - env: Show app environment (paths, directories)
    - android sslpinning disable: Disable SSL pinning
    - android root disable: Disable root detection
    - android hooking list classes: List all classes
    - android keystore list: List keystore entries
    - android clipboard monitor: Monitor clipboard
    """
    package = package.strip()
    if not re.match(r'^[a-zA-Z0-9._]+$', package):
        return f"[ERROR] Invalid package name: {package}"

    cmd = f"objection -g {shlex.quote(package)} explore -c {shlex.quote(command)}"
    return _run_cmd(cmd, timeout=30)
