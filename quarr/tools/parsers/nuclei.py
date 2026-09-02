"""
nuclei.py - Nuclei JSONL output parser.

Parses `nuclei -jsonl` output (one JSON object per line) into finding records.
Pure function.
"""

import json
from typing import Any

from quarr.core.exceptions import ToolOutputParseError


def parse_nuclei_jsonl(raw: str) -> dict[str, Any]:
    if raw is None:
        raise ToolOutputParseError("Nuclei output is None")

    lines = [ln for ln in raw.splitlines() if ln.strip()]
    if not lines:
        # No findings is a valid empty result, not an error.
        return {"findings": []}

    findings = []
    parsed_any = False
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        info = obj.get("info", {})
        findings.append(
            {
                "template_id": obj.get("template-id") or obj.get("templateID"),
                "title": info.get("name") or obj.get("template-id") or "Nuclei finding",
                "severity": info.get("severity", "info"),
                "url": obj.get("matched-at") or obj.get("host"),
                "type": obj.get("type"),
            }
        )

    if not parsed_any:
        raise ToolOutputParseError("No valid JSON lines in nuclei output")

    return {"findings": findings}
