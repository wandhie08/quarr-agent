"""Unit tests for tool output parsers (Phase 2, Req 4)."""

import json as _json
from pathlib import Path

import pytest

from quarr.core.exceptions import ToolOutputParseError
from quarr.parsers.network import parse_tool_output
from quarr.tools.parsers import parse_nikto, parse_nmap_xml, parse_nuclei_jsonl

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    return (FIXTURES / name).read_text()


@pytest.mark.unit
def test_nmap_parses_hosts_and_services():
    result = parse_nmap_xml(_load("nmap.xml"))
    assert len(result["hosts"]) == 1
    host = result["hosts"][0]
    assert host["address"] == "10.10.10.20"
    assert host["hostname"] == "target.lab.local"
    # Only open ports (22, 80) — 443 is closed and excluded.
    assert len(host["services"]) == 2
    ports = {s["port"] for s in host["services"]}
    assert ports == {22, 80}
    ssh = [s for s in host["services"] if s["port"] == 22][0]
    assert ssh["name"] == "ssh"
    assert ssh["product"] == "OpenSSH"


@pytest.mark.unit
def test_nmap_malformed_raises():
    with pytest.raises(ToolOutputParseError):
        parse_nmap_xml("<not valid xml")


@pytest.mark.unit
def test_nmap_empty_raises():
    with pytest.raises(ToolOutputParseError):
        parse_nmap_xml("")


@pytest.mark.unit
def test_nikto_parses_findings():
    result = parse_nikto(_load("nikto.json"))
    assert result["host"] == "10.10.10.20"
    assert len(result["findings"]) == 2
    assert any("clickjacking" in f["title"].lower() for f in result["findings"])


@pytest.mark.unit
def test_nikto_malformed_raises():
    with pytest.raises(ToolOutputParseError):
        parse_nikto("{not json}")


@pytest.mark.unit
def test_nuclei_parses_jsonl():
    result = parse_nuclei_jsonl(_load("nuclei.jsonl"))
    assert len(result["findings"]) == 2
    sevs = {f["severity"] for f in result["findings"]}
    assert "critical" in sevs
    crit = [f for f in result["findings"] if f["severity"] == "critical"][0]
    assert crit["template_id"] == "CVE-2021-41773"


@pytest.mark.unit
def test_nuclei_empty_is_valid_no_findings():
    assert parse_nuclei_jsonl("") == {"findings": []}


@pytest.mark.unit
def test_nuclei_all_invalid_raises():
    with pytest.raises(ToolOutputParseError):
        parse_nuclei_jsonl("not json\nalso not json")


# ---------------------------------------------------------------------------
# Regression: parse_tool_output must recover structured data from the modern
# integration summary format (found via the live agent harness — service
# enumeration was populating hosts with zero services because the summary
# string was re-parsed with the legacy text regex instead of the embedded JSON).
# ---------------------------------------------------------------------------


def _summary(tool_parsed: dict, ok: bool = True) -> str:
    """Reproduce registry._summarize output shape."""
    header = f"[nmap] {'OK' if ok else 'FAILED'}"
    return f"{header}\n{_json.dumps(tool_parsed, indent=2)}"


@pytest.mark.unit
def test_service_enumeration_recovers_services_from_embedded_json():
    parsed = {
        "hosts": [{"address": "127.0.0.1", "services": [
            {"host": "127.0.0.1", "port": 8080, "protocol": "tcp",
             "name": "http", "product": "Apache", "version": "2.4.25"},
        ]}],
        "services": [
            {"host": "127.0.0.1", "port": 8080, "protocol": "tcp",
             "name": "http", "product": "Apache", "version": "2.4.25"},
        ],
    }
    out = parse_tool_output("service_enumeration", _summary(parsed))
    assert len(out["services"]) == 1
    assert out["services"][0]["port"] == 8080
    # A primary host is derived for the state updater.
    assert out["host"] == "127.0.0.1"


@pytest.mark.unit
def test_network_discovery_recovers_hosts_and_total_up():
    parsed = {"hosts": [{"address": "127.0.0.1"}, {"address": "127.0.0.2"}], "services": []}
    out = parse_tool_output("network_discovery", _summary(parsed))
    assert len(out["hosts"]) == 2
    assert out["total_up"] == 2


@pytest.mark.unit
def test_legacy_text_output_still_parsed():
    # Classic nmap text (no embedded JSON header) must still go through NmapParser.
    text = "Nmap scan report for 10.10.10.20\n80/tcp open http Apache 2.4.52\nNmap done"
    out = parse_tool_output("service_enumeration", text)
    assert out["host"] == "10.10.10.20"
    assert any(s["port"] == 80 for s in out["services"])


@pytest.mark.unit
def test_non_integration_output_uses_generic_parser():
    out = parse_tool_output("some_unknown_tool", "just some text output\nline two")
    assert out["tool"] == "some_unknown_tool"
