"""Live Active Directory harness — real impacket/ldap tools against a DC lab (opt-in).

The AD domain had no live tier because it needs a real Windows Domain Controller
(e.g. a GOAD lab). This harness exercises the actual impacket/ldapsearch/rpcclient
binaries end-to-end against a DC you control, and is gated so it NEVER runs by
default or without explicit configuration.

    ┌──────────────┬─────────────────────────────────────────────────────────┐
    │ unit tests   │ mocked _run, canned output -> command-shaping/validation  │
    │ LIVE (here)  │ real impacket/ldap vs a DC -> it actually works           │
    └──────────────┴─────────────────────────────────────────────────────────┘

SAFETY / OPT-IN (two tiers)
---------------------------
Tier 1 — read-only enumeration (unauthenticated or low-touch):
    export QUARR_LIVE_AD_DC="10.10.10.10"      # your lab DC IP (required)
    export QUARR_LIVE_AD_DOMAIN="corp.local"   # domain FQDN (required)
    pytest tests/test_live_ad.py -m live -v

Tier 2 — authenticated / more intrusive (Kerberoast, DCSync/secretsdump).
These modify nothing but require valid domain credentials and pull hashes, so
they are behind a SECOND opt-in plus credentials:
    export QUARR_LIVE_AD_AUTH=1
    export QUARR_LIVE_AD_USER="svc_user"
    export QUARR_LIVE_AD_PASS="Password123"

If QUARR_LIVE_AD_DC is unset the whole module skips. If a required binary is
missing, that individual test skips (not fails).

Recommended lab: GOAD (github.com/Orange-Cyberdefense/GOAD) or GOAD-Light.
Never point this at a domain you are not authorized to test.
"""

import os
import shutil

import pytest

from quarr.tools import active_directory as ad

pytestmark = pytest.mark.live

DC = os.environ.get("QUARR_LIVE_AD_DC")
DOMAIN = os.environ.get("QUARR_LIVE_AD_DOMAIN", "")
AUTH_ENABLED = os.environ.get("QUARR_LIVE_AD_AUTH") == "1"
AD_USER = os.environ.get("QUARR_LIVE_AD_USER", "")
AD_PASS = os.environ.get("QUARR_LIVE_AD_PASS", "")

if not DC:
    pytest.skip(
        "QUARR_LIVE_AD_DC not set — skipping live Active Directory harness. "
        "See module docstring to opt in (needs a DC lab such as GOAD).",
        allow_module_level=True,
    )


def require(binary: str):
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed on this host")


def assert_reached_tool(out: str):
    """A live run must return a string and must have actually invoked the tool
    (not been blocked by input validation or a missing binary)."""
    assert isinstance(out, str) and out.strip() != ""
    assert "Invalid target" not in out
    assert "Command not found" not in out


# ===========================================================================
# Tier 1 — read-only enumeration
# ===========================================================================

@pytest.mark.live
class TestLiveADEnum:
    def test_ldap_search_reaches_dc(self):
        require("ldapsearch")
        out = ad.ldap_search(target=DC)
        assert_reached_tool(out)
        # Either it returned LDAP data or a connection/anon-bind message —
        # never a validation/crash error.

    def test_rpc_enum_null_session(self):
        require("rpcclient")
        out = ad.rpc_enum(target=DC)
        assert_reached_tool(out)

    def test_asrep_roast_runs(self):
        require("impacket-GetNPUsers")
        if not DOMAIN:
            pytest.skip("QUARR_LIVE_AD_DOMAIN not set — required for AS-REP roast")
        out = ad.kerberos_asrep_roast(target=DC, domain=DOMAIN)
        assert_reached_tool(out)
        # A real GetNPUsers run either finds AS-REP-roastable users or reports
        # none; both are well-formed, non-crashing outcomes.


# ===========================================================================
# Tier 2 — authenticated / intrusive (double opt-in + credentials)
# ===========================================================================

@pytest.mark.live
@pytest.mark.skipif(
    not (AUTH_ENABLED and AD_USER and AD_PASS),
    reason="QUARR_LIVE_AD_AUTH/USER/PASS not set — skipping authenticated AD tests",
)
class TestLiveADAuthenticated:
    def test_kerberoast_with_creds(self):
        require("impacket-GetUserSPNs")
        if not DOMAIN:
            pytest.skip("QUARR_LIVE_AD_DOMAIN not set")
        out = ad.kerberos_kerberoast(target=DC, domain=DOMAIN,
                                     username=AD_USER, password=AD_PASS)
        assert_reached_tool(out)

    def test_ldap_authenticated_search(self):
        require("ldapsearch")
        out = ad.ldap_search(target=DC, username=AD_USER, password=AD_PASS)
        assert_reached_tool(out)

    def test_secrets_dump_dcsync(self):
        # DCSync-style secretsdump — only with an account that has the rights.
        require("impacket-secretsdump")
        out = ad.secrets_dump(target=DC, username=AD_USER, password=AD_PASS,
                              domain=DOMAIN)
        assert_reached_tool(out)
        # Success dumps NTLM hashes; insufficient privilege returns an impacket
        # error string — both prove the integration executed end-to-end.
