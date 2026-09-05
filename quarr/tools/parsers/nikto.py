"""
nikto.py - Nikto output parser.

Parses Nikto JSON output (`-Format json`) into finding records. Pure function.
"""

import json
from typing import Any

from quarr.core.exceptions import ToolOutputParseError


def parse_nikto(raw: str) -> dict[str, Any]:
    if not raw or not raw.strip():
        raise ToolOutputParseError("Empty nikto output")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ToolOutputParseError("Malformed nikto JSON", context={"error": str(e)}) from e

    # Nikto JSON may be a dict with "vulnerabilities" or a list of hosts.
    vulns = []
    if isinstance(data, dict):
        vulns = data.get("vulnerabilities", [])
        host = data.get("host") or data.get("ip")
    elif isinstance(data, list) and data:
        first = data[0]
        vulns = first.get("vulnerabilities", []) if isinstance(first, dict) else []
        host = first.get("host") if isinstance(first, dict) else None
    else:
        host = None

    findings = []
    for v in vulns:
        if not isinstance(v, dict):
            continue  # skip malformed entries instead of crashing
        findings.append(
            {
                "id": v.get("id"),
                "title": v.get("msg") or v.get("title") or "Nikto finding",
                "url": v.get("url"),
                "method": v.get("method", "GET"),
                "asset": host,
                "severity": "info",
            }
        )

    return {"host": host, "findings": findings}
