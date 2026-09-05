"""Unit tests for the mobile pentest toolset (quarr/tools/mobile.py).

mobile.py was the least-covered module (~12%). These tests exercise the real
DETECTION and VALIDATION logic rather than the subprocess plumbing:

  STATIC (real file parsing against fixtures/apk_decoded)
    - apk_manifest_analysis: debuggable/backup/cleartext flags, exported
      components (activity/service/receiver/provider), deeplinks, SDK,
      dangerous permissions.
    - apk_network_config: cleartext domains, user trust anchors, missing pinning,
      debug overrides.

  STATIC (subprocess mocked)
    - apk_secrets_scan: grep command shape + result framing.
    - apk_cert_check: debug-cert / weak-algorithm / V1-only detection.

  PATH SAFETY
    - _validate_path rejects traversal and sensitive roots.

  DYNAMIC (subprocess mocked)
    - package-name validation rejects injection on every ADB/Frida tool.
    - adb_logcat_check flags secrets in captured logs.
    - adb_storage_check surfaces sensitive SharedPreferences data.

No real device, apktool, jadx, frida, or adb is invoked.
"""

from pathlib import Path

import pytest

from quarr.tools import mobile as m

FIXTURES = Path(__file__).parent / "fixtures"
APK_DIR = str(FIXTURES / "apk_decoded")


# =========================================================================== #
# Path safety
# =========================================================================== #

@pytest.mark.unit
class TestValidatePath:
    def test_rejects_traversal(self):
        with pytest.raises(ValueError):
            m._validate_path("/tmp/apk/../../etc/passwd")

    def test_rejects_etc(self):
        with pytest.raises(ValueError):
            m._validate_path("/etc/shadow")

    def test_rejects_root(self):
        with pytest.raises(ValueError):
            m._validate_path("/root/.ssh/id_rsa")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            m._validate_path("   ")

    def test_allows_normal_tmp_path(self):
        assert m._validate_path("/tmp/quarr_apk/bankapp") == "/tmp/quarr_apk/bankapp"


# =========================================================================== #
# Static: manifest analysis (real file parsing)
# =========================================================================== #

@pytest.mark.unit
class TestManifestAnalysis:
    def test_detects_critical_debuggable(self):
        out = m.apk_manifest_analysis(APK_DIR)
        assert "[CRITICAL]" in out
        assert "debuggable" in out.lower()

    def test_detects_backup_and_cleartext_high(self):
        out = m.apk_manifest_analysis(APK_DIR)
        assert "allowBackup" in out
        assert "usesCleartextTraffic" in out

    def test_detects_all_exported_component_types(self):
        out = m.apk_manifest_analysis(APK_DIR)
        assert "exported activities" in out
        assert "exported services" in out
        assert "exported receivers" in out
        assert "exported content providers" in out  # HIGH — data leak

    def test_reports_package_and_sdk_and_permissions(self):
        out = m.apk_manifest_analysis(APK_DIR)
        assert "com.vulnerable.bankapp" in out
        assert "minSdkVersion: 19" in out
        assert "READ_SMS" in out
        # minSdk < 24 raises a MEDIUM finding.
        assert "minSdkVersion=19" in out

    def test_detects_custom_deeplink_scheme(self):
        out = m.apk_manifest_analysis(APK_DIR)
        assert "deeplink" in out.lower()
        assert "bankapp" in out

    def test_missing_manifest_returns_error(self, tmp_path):
        out = m.apk_manifest_analysis(str(tmp_path))
        assert "[ERROR]" in out and "AndroidManifest.xml not found" in out


# =========================================================================== #
# Static: network security config (real file parsing)
# =========================================================================== #

@pytest.mark.unit
class TestNetworkConfig:
    def test_flags_cleartext_domain(self):
        out = m.apk_network_config(APK_DIR)
        assert "Cleartext traffic allowed" in out
        assert "staging.bankapp.example.com" in out

    def test_flags_user_trust_anchor(self):
        out = m.apk_network_config(APK_DIR)
        assert "User-installed certificates trusted" in out

    def test_flags_missing_pinning(self):
        out = m.apk_network_config(APK_DIR)
        assert "No certificate pinning configured" in out

    def test_flags_debug_overrides(self):
        out = m.apk_network_config(APK_DIR)
        assert "Debug overrides present" in out

    def test_absent_config_reports_platform_defaults(self, tmp_path):
        # A directory with no config file and no `find` hit → platform defaults.
        out = m.apk_network_config(str(tmp_path))
        assert "platform defaults" in out.lower()


# =========================================================================== #
# Static: secrets scan (subprocess mocked)
# =========================================================================== #

@pytest.mark.unit
class TestSecretsScan:
    def test_frames_found_secrets_and_endpoints(self, monkeypatch):
        calls = []

        def fake_shell(cmd, timeout=60):
            calls.append(cmd)
            if "https?://" in cmd:  # the URL/endpoint grep
                return "Api.java:15:https://api.bankapp.example.com/v1/transfer"
            return "Config.smali:88:api_key = AIzaSyD1234567890abcdefghijklmnop"

        monkeypatch.setattr(m, "_run_shell", fake_shell)
        out = m.apk_secrets_scan("/tmp/quarr_apk/src")

        assert "SECRETS FOUND" in out
        assert "api_key" in out
        assert "API ENDPOINTS IN SOURCE" in out
        # The secrets grep must restrict to source file types and use -E.
        secrets_cmd = calls[0]
        assert "--include='*.java'" in secrets_cmd and "-E" in secrets_cmd

    def test_reports_none_when_clean(self, monkeypatch):
        monkeypatch.setattr(m, "_run_shell", lambda cmd, timeout=60: "[No output]")
        out = m.apk_secrets_scan("/tmp/quarr_apk/src")
        assert "SECRETS: None found" in out
        assert "API ENDPOINTS: None found" in out


# =========================================================================== #
# Static: certificate check (subprocess mocked)
# =========================================================================== #

@pytest.mark.unit
class TestCertCheck:
    def test_detects_debug_certificate(self, monkeypatch):
        monkeypatch.setattr(
            m, "_run_cmd",
            lambda cmd, timeout=15: "Signer #1 certificate DN: CN=Android Debug, O=Android, C=US",
        )
        out = m.apk_cert_check("/tmp/app.apk")
        assert "[CRITICAL]" in out
        assert "DEBUG certificate" in out

    def test_detects_weak_algorithm(self, monkeypatch):
        monkeypatch.setattr(
            m, "_run_cmd",
            lambda cmd, timeout=15: "Signature algorithm: SHA1withRSA, 2048-bit key",
        )
        out = m.apk_cert_check("/tmp/app.apk")
        assert "Weak signature algorithm" in out

    def test_detects_v1_only_janus(self, monkeypatch):
        monkeypatch.setattr(
            m, "_run_cmd",
            lambda cmd, timeout=15: "Verified using v1 scheme (JAR signing): true",
        )
        out = m.apk_cert_check("/tmp/app.apk")
        assert "Janus" in out or "V1 signing" in out


# =========================================================================== #
# Dynamic: package-name validation rejects injection everywhere
# =========================================================================== #

@pytest.mark.unit
class TestDynamicInputValidation:
    BAD = "com.app; rm -rf /"

    def test_adb_app_info_rejects_bad_package(self):
        assert "[ERROR]" in m.adb_app_info(self.BAD)

    def test_adb_storage_check_rejects_bad_package(self):
        assert "[ERROR]" in m.adb_storage_check(self.BAD)

    def test_adb_logcat_check_rejects_bad_package(self):
        assert "[ERROR]" in m.adb_logcat_check(self.BAD)

    def test_frida_ssl_bypass_rejects_bad_package(self):
        assert "[ERROR]" in m.frida_ssl_bypass(self.BAD)

    def test_objection_explore_rejects_bad_package(self):
        assert "[ERROR]" in m.objection_explore(self.BAD)


# =========================================================================== #
# Dynamic: detection logic (subprocess mocked)
# =========================================================================== #

@pytest.mark.unit
class TestDynamicDetection:
    def test_logcat_flags_secrets_in_logs(self, monkeypatch):
        log = (
            "D/Auth: login password=hunter2\n"
            "D/Net: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc\n"
            "D/User: contact user@example.com\n"
        )
        # First _run_cmd clears logcat; _run_shell captures. Patch both.
        monkeypatch.setattr(m, "_run_cmd", lambda cmd, timeout=3: "")
        monkeypatch.setattr(m, "_run_shell", lambda cmd, timeout=10: log)

        out = m.adb_logcat_check("com.vulnerable.bankapp")
        assert "SENSITIVE DATA IN LOGS" in out
        assert "password=hunter2" in out

    def test_logcat_clean_reports_nothing_sensitive(self, monkeypatch):
        monkeypatch.setattr(m, "_run_cmd", lambda cmd, timeout=3: "")
        monkeypatch.setattr(m, "_run_shell", lambda cmd, timeout=10:
                            "D/App: onCreate\nD/App: rendered view\n")
        out = m.adb_logcat_check("com.vulnerable.bankapp")
        assert "No obvious sensitive data" in out

    def test_storage_check_surfaces_sensitive_shared_prefs(self, monkeypatch):
        prefs = (
            '<map>\n'
            '  <string name="auth_token">eyJ0okenValue</string>\n'
            '  <string name="user_password">s3cr3t</string>\n'
            '  <string name="theme">dark</string>\n'
            '</map>\n'
        )
        # adb_storage_check calls _run_shell repeatedly; return prefs for the
        # shared_prefs read and empty for the rest.
        def fake_shell(cmd, timeout=10):
            if "shared_prefs" in cmd:
                return prefs
            return "[No output]"

        monkeypatch.setattr(m, "_run_shell", fake_shell)
        out = m.adb_storage_check("com.vulnerable.bankapp")
        assert "SENSITIVE DATA in SharedPreferences" in out or "SENSITIVE DATA IN SharedPreferences" in out
        assert "auth_token" in out or "password" in out.lower()
