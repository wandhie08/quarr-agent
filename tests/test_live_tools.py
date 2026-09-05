"""Live integration harness — real tools against a real lab target (Opsi C).

This is the deepest testing tier: it executes the ACTUAL security-tool binaries
(nmap, nikto, nuclei, ...) end-to-end — build command -> run subprocess ->
parse real output — and asserts the integration produces a well-formed
ToolResult. Unlike the unit tests, nothing here is mocked.

    ┌─────────────┬──────────────────────────────────────────────────────────┐
    │ unit tests  │ mock executor, canned output   -> logic correctness       │
    │ edge cases  │ mock executor, messy output    -> robustness              │
    │ LIVE (here) │ real binary, real target       -> it actually works       │
    └─────────────┴──────────────────────────────────────────────────────────┘

SAFETY / OPT-IN
---------------
Every test is marked `@pytest.mark.live` and the default pytest config runs
`-m 'not live'`, so these NEVER run in CI or a normal `pytest` invocation.
They only run when you explicitly opt in AND point them at a target you own:

    export QUARR_LIVE_TARGET="127.0.0.1"          # a lab box you control
    export QUARR_LIVE_URL="http://127.0.0.1:8080" # optional, for web tools
    pytest tests/test_live_tools.py -m live -v

If QUARR_LIVE_TARGET is unset, the whole module is skipped. If a given tool
binary is not installed, that individual test is skipped (not failed).

Recommended targets: a local vulnerable-app container you own, e.g.
    docker run --rm -p 8080:80 vulnerables/web-dvwa
    docker run --rm -p 3000:3000 bkimminich/juice-shop
Never point these at a host you are not authorised to scan.
"""

import os
import re
import shutil

import pytest

from quarr.tools.integrations.base import ToolResult
from quarr.tools.integrations.masscan import MasscanIntegration
from quarr.tools.integrations.nikto import NiktoIntegration
from quarr.tools.integrations.nmap import NmapIntegration
from quarr.tools.integrations.nuclei import NucleiIntegration
from quarr.tools.integrations.sslscan import SSLScanIntegration
from quarr.tools.integrations.whatweb import WhatWebIntegration

pytestmark = pytest.mark.live

LIVE_TARGET = os.environ.get("QUARR_LIVE_TARGET")
LIVE_URL = os.environ.get("QUARR_LIVE_URL") or (
    f"http://{LIVE_TARGET}" if LIVE_TARGET else None
)
# Optional second, richer web target (e.g. OWASP Juice Shop on :3000).
# export QUARR_LIVE_URL2="http://127.0.0.1:3000"
LIVE_URL2 = os.environ.get("QUARR_LIVE_URL2")

# The port the primary web app is expected to expose (parsed from LIVE_URL).
def _expected_web_port(url):
    if not url:
        return None
    m = re.search(r":(\d+)", url)
    return int(m.group(1)) if m else (443 if url.startswith("https") else 80)


EXPECTED_WEB_PORT = _expected_web_port(LIVE_URL)


def _service_scan_ports():
    """Port range for the service-scan test.

    Always scan the common 1-1024 range PLUS the actual web port, so the test
    works whether the lab app listens on 80/443 or a high port like 8080/3000.
    Scanning only 1-1024 would silently miss a high-port web app and fail.
    """
    if EXPECTED_WEB_PORT and EXPECTED_WEB_PORT > 1024:
        return f"1-1024,{EXPECTED_WEB_PORT}"
    return "1-1024"


# Bounded nuclei run for the live harness: a full template scan can take many
# minutes and blow the pytest timeout. Restricting to fast tech/http templates
# with tight per-request timeouts keeps a real scan to ~30s while still
# exercising the real binary + JSONL parser. Operators who want a full scan can
# set QUARR_LIVE_NUCLEI_FULL=1.
_NUCLEI_FULL = os.environ.get("QUARR_LIVE_NUCLEI_FULL") == "1"
NUCLEI_BOUNDED_ARGS = (
    None if _NUCLEI_FULL else
    ["-tags", "tech,http", "-timeout", "5", "-retries", "1", "-rate-limit", "50"]
)

# Skip the entire module unless the operator opted in with a target.
if not LIVE_TARGET:
    pytest.skip(
        "QUARR_LIVE_TARGET not set — skipping live tool harness. "
        "See module docstring to opt in.",
        allow_module_level=True,
    )


def require(binary: str):
    """Skip an individual test if the tool binary is not installed."""
    if shutil.which(binary) is None:
        pytest.skip(f"{binary} not installed on this host")


def assert_wellformed(result: ToolResult, expect_key: str):
    """A live run must return a ToolResult; on success the parsed dict is shaped correctly."""
    assert isinstance(result, ToolResult)
    # Either it parsed successfully (parsed has the expected key) or it failed
    # gracefully with an error message — never an unhandled crash.
    if result.success:
        assert expect_key in result.parsed
    else:
        assert result.error, "failed runs must carry an error message"


@pytest.mark.live
class TestLiveNetwork:
    def test_nmap_service_scan_detects_web_port(self):
        require("nmap")
        result = NmapIntegration(mode="service").run(target=LIVE_TARGET, ports=_service_scan_ports())
        assert result.success, f"nmap failed: {result.error}"
        # Deep assertion: the web app's port must actually be discovered open.
        ports = {s["port"] for s in result.parsed["services"]}
        assert EXPECTED_WEB_PORT in ports, (
            f"expected open port {EXPECTED_WEB_PORT} in {sorted(ports)}"
        )
        # And it should be identified as an HTTP-ish service.
        web_svc = next(s for s in result.parsed["services"] if s["port"] == EXPECTED_WEB_PORT)
        assert web_svc["name"] and "http" in web_svc["name"].lower()

    def test_nmap_discovery_host_up(self):
        require("nmap")
        result = NmapIntegration(mode="discovery").run(target=LIVE_TARGET)
        assert result.success, f"nmap failed: {result.error}"
        # The lab host must be reported as up.
        assert len(result.parsed["hosts"]) >= 1
        assert result.parsed["hosts"][0]["state"] == "up"

    def test_masscan_top_ports(self):
        require("masscan")
        # masscan usually needs root; a graceful failure is acceptable here.
        result = MasscanIntegration().run(target=LIVE_TARGET, ports="1-1024", rate="1000")
        assert_wellformed(result, "services")


@pytest.mark.live
class TestLiveWeb:
    def test_whatweb_finds_technology(self):
        require("whatweb")
        assert LIVE_URL
        result = WhatWebIntegration().run(target=LIVE_URL)
        assert result.success, f"whatweb failed: {result.error}"
        # Deep assertion: a real web server exposes at least one fingerprint.
        assert len(result.parsed["technologies"]) >= 1

    def test_nuclei_scan(self):
        require("nuclei")
        assert LIVE_URL
        result = NucleiIntegration().run(target=LIVE_URL, extra_args=NUCLEI_BOUNDED_ARGS)
        # Empty findings is a valid successful result; every finding must be shaped.
        assert_wellformed(result, "findings")
        if result.success:
            for f in result.parsed["findings"]:
                assert "severity" in f and "template_id" in f

    def test_nikto_scan(self):
        require("nikto")
        assert LIVE_URL
        result = NiktoIntegration().run(target=LIVE_URL)
        assert_wellformed(result, "findings")

    def test_sslscan_analysis(self):
        require("sslscan")
        result = SSLScanIntegration().run(target=LIVE_TARGET)
        assert_wellformed(result, "protocols")


@pytest.mark.live
@pytest.mark.skipif(not LIVE_URL2, reason="QUARR_LIVE_URL2 not set (optional richer target, e.g. Juice Shop)")
class TestLiveRicherTarget:
    """Optional deeper target such as OWASP Juice Shop (a modern SPA at :3000)."""

    def test_whatweb_fingerprints_spa(self):
        require("whatweb")
        result = WhatWebIntegration().run(target=LIVE_URL2)
        assert result.success, f"whatweb failed: {result.error}"
        assert len(result.parsed["technologies"]) >= 1

    def test_nuclei_scans_spa(self):
        require("nuclei")
        result = NucleiIntegration().run(target=LIVE_URL2, extra_args=NUCLEI_BOUNDED_ARGS)
        assert_wellformed(result, "findings")
