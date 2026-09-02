"""Output parsers for tool integrations (Phase 2)."""

from quarr.tools.parsers.nikto import parse_nikto
from quarr.tools.parsers.nmap import parse_nmap_xml
from quarr.tools.parsers.nuclei import parse_nuclei_jsonl

__all__ = ["parse_nmap_xml", "parse_nikto", "parse_nuclei_jsonl"]
