"""Security & robustness tests for the deep-audit fixes.

Covers:
  - persistence.py: engagement-id/filename validation blocks path traversal.
  - secrets.redact(): extended coverage (secret/token/credential KV, JWT,
    GitHub/Slack tokens, basic-auth URLs).
  - command validator: URL query/fragment chars allowed; shell metachars still
    blocked.
  - registry.py: nuclei severity + gobuster mode/wordlist validated.
  - parsers: nmap/nikto/masscan tolerate malformed (non-dict / missing attr)
    output instead of crashing.
  - api/security: assert_secure_config fails closed on the default JWT secret.
"""

import pytest

from quarr.core import persistence as ps
from quarr.core.exceptions import ValidationError
from quarr.core.secrets import redact

# =========================================================================== #
# persistence path traversal
# =========================================================================== #

@pytest.mark.unit
class TestPersistenceTraversal:
    def test_get_engagement_dir_rejects_traversal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ps, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
        with pytest.raises(ValidationError):
            ps._get_engagement_dir("../../etc")

    def test_load_state_rejects_traversal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ps, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
        with pytest.raises(ValidationError):
            ps.load_state("../../../tmp/evil")

    def test_delete_engagement_rejects_traversal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ps, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
        with pytest.raises(ValidationError):
            ps.delete_engagement("../../somedir")

    def test_save_evidence_rejects_traversal_filename(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ps, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
        with pytest.raises(ValidationError):
            ps.save_evidence("ENG-1", "../../evil.txt", "x")

    def test_valid_id_and_filename_work(self, tmp_path, monkeypatch):
        monkeypatch.setattr(ps, "ENGAGEMENTS_DIR", str(tmp_path / "engagements"))
        path = ps.save_evidence("ENG-abc123", "note.txt", "hello")
        assert path.endswith("ENG-abc123/evidence/note.txt")


# =========================================================================== #
# secrets.redact() extended coverage
# =========================================================================== #

@pytest.mark.unit
class TestRedactCoverage:
    @pytest.mark.parametrize("text,secret", [
        ("secret=hunter2topsecret", "hunter2topsecret"),
        ("token: abc123def456ghi", "abc123def456ghi"),
        ("credential = mypass123", "mypass123"),
        ("authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ("aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
         "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
    ])
    def test_kv_secrets_redacted(self, text, secret):
        out = redact(text)
        assert secret not in out
        assert "***REDACTED***" in out

    def test_jwt_redacted(self):
        # Assemble at runtime so the literal token never appears in source
        # (keeps GitHub/secret scanners happy while still testing redaction).
        jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjMifQ" + "." + "SflKxwRJSMeKKF2QT4"
        assert jwt not in redact(f"auth was {jwt} ok")

    def test_github_token_redacted(self):
        tok = "ghp_" + "1234567890abcdefghijklmnopqrstuvwx"
        assert tok not in redact(tok)

    def test_slack_token_redacted(self):
        tok = "xoxb-" + "1234567890-abcdefghijklmnop"
        assert tok not in redact(tok)

    def test_basic_auth_url_redacted(self):
        out = redact("connect to https://admin:s3cr3t@internal.host/api")
        assert "s3cr3t" not in out
        assert "internal.host" in out  # host preserved, only creds masked

    def test_password_still_works(self):
        assert "hunter2" not in redact("password=hunter2")

    def test_non_secret_text_untouched(self):
        assert redact("just a normal finding description") == "just a normal finding description"


# =========================================================================== #
# command validator: URL chars allowed, shell metachars blocked
# =========================================================================== #

@pytest.mark.unit
class TestCommandValidator:
    def test_parameterized_url_allowed(self):
        from quarr.core.validators.command import validate_arg
        assert validate_arg("http://site.com/p?id=1&x=2") == "http://site.com/p?id=1&x=2"

    @pytest.mark.parametrize("bad", ["a;b", "a|b", "$(x)", "`x`", "a>b", "a<b"])
    def test_shell_metachars_still_blocked(self, bad):
        from quarr.core.exceptions import ArgumentValidationError
        from quarr.core.validators.command import validate_arg
        with pytest.raises(ArgumentValidationError):
            validate_arg(bad)


# =========================================================================== #
# registry argument validation
# =========================================================================== #

@pytest.mark.unit
class TestRegistryArgValidation:
    def test_vulnerability_scan_rejects_bad_severity(self):
        from quarr.tools.registry import vulnerability_scan
        out = vulnerability_scan("http://10.0.0.1", severity="high -t http://evil/x.yaml")
        assert "[ERROR]" in out and "Invalid severity" in out

    def test_web_content_discovery_rejects_bad_mode(self, monkeypatch):
        import quarr.tools.registry as reg
        # Avoid running the real tool if mode passes; but bad mode returns early.
        out = reg.web_content_discovery("http://10.0.0.1", wordlist="common", mode="dir -x php")
        assert "[ERROR]" in out and "Invalid mode" in out

    def test_web_content_discovery_rejects_unknown_wordlist(self):
        from quarr.tools.registry import web_content_discovery
        out = web_content_discovery("http://10.0.0.1", wordlist="/etc/passwd", mode="dir")
        assert "[ERROR]" in out and "Unknown wordlist" in out


# =========================================================================== #
# parser robustness
# =========================================================================== #

@pytest.mark.unit
class TestParserRobustness:
    def test_nmap_skips_port_without_portid(self):
        from quarr.tools.parsers.nmap import parse_nmap_xml
        xml = (
            '<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>'
            '<ports><port protocol="tcp"><state state="open"/></port>'  # no portid
            '<port protocol="tcp" portid="80"><state state="open"/>'
            '<service name="http"/></port></ports></host></nmaprun>'
        )
        result = parse_nmap_xml(xml)
        ports = {s["port"] for s in result["hosts"][0]["services"]}
        assert ports == {80}  # malformed port skipped, valid one kept

    def test_nikto_skips_non_dict_vuln(self):
        from quarr.tools.parsers.nikto import parse_nikto
        result = parse_nikto('{"host": "10.0.0.1", "vulnerabilities": ["junk", {"id": "1", "msg": "real"}]}')
        # Only the well-formed dict entry becomes a finding; no crash.
        assert len(result["findings"]) == 1
        assert result["findings"][0]["title"] == "real"

    def test_masscan_skips_non_dict_records(self):
        from quarr.tools.integrations.masscan import MasscanIntegration
        parsed = MasscanIntegration().parse_output('["junk", {"ip": "10.0.0.1", "ports": [{"port": 80}]}]')
        assert parsed["services"] == [{"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open"}]


# =========================================================================== #
# API: fail closed on insecure JWT secret
# =========================================================================== #

@pytest.mark.unit
class TestJWTStartupGuard:
    def test_assert_secure_config_rejects_default_secret(self):
        from quarr.api import security as sec
        from quarr.api.auth import UserStore
        from quarr.core.config import Settings

        sec.init_security(
            Settings(_env_file=None, jwt_secret="change-me-in-production-quarr-jwt-secret"),
            UserStore(),
        )
        with pytest.raises(RuntimeError, match="insecure default"):
            sec.assert_secure_config()

    def test_assert_secure_config_accepts_strong_secret(self):
        from quarr.api import security as sec
        from quarr.api.auth import UserStore
        from quarr.core.config import Settings

        sec.init_security(Settings(_env_file=None, jwt_secret="x" * 40), UserStore())
        sec.assert_secure_config()  # must not raise
