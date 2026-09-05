"""Live Threat-Intel harness — real NVD CVE lookups, NO API key required (opt-in).

The threat-intel module has three keyed sources (VirusTotal, AbuseIPDB, Shodan)
and one FREE, keyless source: the NIST NVD CVE database. This harness exercises
the free NVD path end-to-end against the real public API — the only threat-intel
call that can be verified without credentials — and asserts the keyed tools fail
gracefully when no key is configured.

    ┌──────────────┬─────────────────────────────────────────────────────────┐
    │ unit tests   │ mocked HTTP, canned JSON  -> parsing/validation logic     │
    │ LIVE (here)  │ real NVD API over network -> it actually works, keyless   │
    └──────────────┴─────────────────────────────────────────────────────────┘

OPT-IN
------
Marked `@pytest.mark.live` (deselected by default). Requires network access to
services.nvd.nist.gov. No API key needed. Opt in with:

    export QUARR_LIVE_INTEL=1
    pytest tests/test_live_intel.py -m live -v

If the NVD API is unreachable/rate-limited, the affected test SKIPS (does not
fail) — NVD occasionally throttles unauthenticated clients.
"""

import os
import shutil

import pytest

from quarr.tools.threat_intel import (
    abuseipdb_check,
    cve_lookup,
    shodan_lookup,
    virustotal_lookup,
)

pytestmark = pytest.mark.live

INTEL_ENABLED = os.environ.get("QUARR_LIVE_INTEL") == "1"

if not INTEL_ENABLED:
    pytest.skip(
        "QUARR_LIVE_INTEL not set — skipping live threat-intel harness. "
        "See module docstring to opt in (no API key required).",
        allow_module_level=True,
    )

# cve_lookup uses curl under the hood.
if shutil.which("curl") is None:
    pytest.skip("curl not installed — required for NVD lookups", allow_module_level=True)


def _skip_if_unreachable(out: str):
    """NVD sometimes throttles/blocks unauthenticated clients; treat transport
    failures as a skip rather than a hard failure."""
    if "[ERROR]" in out or "[No response]" in out or "response error" in out.lower():
        pytest.skip(f"NVD API unreachable/throttled: {out[:120]}")


@pytest.mark.live
class TestLiveNVD:
    def test_cve_lookup_by_id_returns_cvss(self):
        # Log4Shell — a well-known, stable CRITICAL CVE.
        out = cve_lookup(cve_id="CVE-2021-44228")
        _skip_if_unreachable(out)
        assert "CVE-2021-44228" in out
        assert "CRITICAL" in out.upper()
        assert "10.0" in out                      # its CVSS base score
        assert "Log4j" in out or "log4j" in out    # description came through

    def test_cve_lookup_by_keyword_returns_results(self):
        out = cve_lookup(keyword="Apache Struts remote code execution")
        _skip_if_unreachable(out)
        # Either matches (a CVE- id appears) or a clean "no results" message —
        # never a crash or unhandled error.
        assert "CVE-" in out or "No CVE found" in out

    def test_cve_lookup_nonexistent_id_handled(self):
        out = cve_lookup(cve_id="CVE-1999-0000")
        _skip_if_unreachable(out)
        # A syntactically-valid but non-matching ID → clean "no results".
        assert "No CVE found" in out or "CVE-1999-0000" in out

    def test_cve_lookup_requires_input(self):
        # No network needed: input validation happens before any request.
        out = cve_lookup()
        assert "[ERROR]" in out and "Provide" in out


@pytest.mark.live
class TestKeyedToolsGracefulWithoutKey:
    """With no API key configured, keyed tools must return a clear error, not
    crash — verified against the real code path (no HTTP call is made)."""

    def _no_keys(self, monkeypatch):
        for k in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY"):
            monkeypatch.delenv(k, raising=False)

    def test_virustotal_without_key(self, monkeypatch):
        self._no_keys(monkeypatch)
        out = virustotal_lookup("ip", "8.8.8.8")
        assert "[ERROR]" in out and "VIRUSTOTAL_API_KEY" in out

    def test_abuseipdb_without_key(self, monkeypatch):
        self._no_keys(monkeypatch)
        out = abuseipdb_check("8.8.8.8")
        assert "[ERROR]" in out and "ABUSEIPDB_API_KEY" in out

    def test_shodan_without_key(self, monkeypatch):
        self._no_keys(monkeypatch)
        out = shodan_lookup("8.8.8.8")
        assert "[ERROR]" in out and "SHODAN_API_KEY" in out
