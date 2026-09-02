"""Unit tests for tool output parsers (Phase 2, Req 4)."""

from pathlib import Path

import pytest

from quarr.tools.parsers import parse_nmap_xml, parse_nikto, parse_nuclei_jsonl
from quarr.core.exceptions import ToolOutputParseError

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
