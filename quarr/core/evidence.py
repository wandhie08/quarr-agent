"""
evidence.py - M17: Evidence Collector

Structured evidence collection untuk findings.
Setiap evidence punya: timestamp, source, type, content, finding_id.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, field


@dataclass
class Evidence:
    id: str
    finding_id: str
    source_tool: str
    evidence_type: str  # "tool_output", "screenshot", "request_response", "file", "note"
    description: str
    content: str = ""
    filepath: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class EvidenceCollector:
    """Manage evidence for an engagement."""

    def __init__(self, engagement_id: str, base_dir: str = "engagements"):
        self.engagement_id = engagement_id
        self.evidence_dir = Path(base_dir) / engagement_id / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.evidence: List[Evidence] = []
        self._counter = 0

    def collect(
        self,
        finding_id: str,
        source_tool: str,
        description: str,
        content: str = "",
        evidence_type: str = "tool_output",
    ) -> Evidence:
        """Collect a piece of evidence."""
        self._counter += 1
        ev = Evidence(
            id=f"EV-{self._counter:04d}",
            finding_id=finding_id,
            source_tool=source_tool,
            evidence_type=evidence_type,
            description=description,
            content=content[:5000],
        )

        # Save to file
        filename = f"{ev.id}_{source_tool}.txt"
        filepath = self.evidence_dir / filename
        with open(filepath, "w") as f:
            f.write(f"Evidence: {ev.id}\n")
            f.write(f"Finding: {finding_id}\n")
            f.write(f"Tool: {source_tool}\n")
            f.write(f"Type: {evidence_type}\n")
            f.write(f"Time: {ev.timestamp}\n")
            f.write(f"Description: {description}\n")
            f.write(f"---\n{content}\n")
        ev.filepath = str(filepath)

        self.evidence.append(ev)
        return ev

    def collect_request_response(
        self,
        finding_id: str,
        request: str,
        response: str,
        description: str = "",
    ) -> Evidence:
        """Collect HTTP request/response pair."""
        content = f"=== REQUEST ===\n{request}\n\n=== RESPONSE ===\n{response}"
        return self.collect(
            finding_id=finding_id,
            source_tool="http_capture",
            description=description or "HTTP request/response capture",
            content=content,
            evidence_type="request_response",
        )

    def get_for_finding(self, finding_id: str) -> List[Evidence]:
        return [e for e in self.evidence if e.finding_id == finding_id]

    def summary(self) -> str:
        if not self.evidence:
            return "No evidence collected"
        lines = [f"Evidence collected: {len(self.evidence)}"]
        for ev in self.evidence:
            lines.append(f"  {ev.id} [{ev.evidence_type}] {ev.description[:60]}")
        return "\n".join(lines)

    def save_index(self) -> str:
        """Save evidence index as JSON."""
        filepath = self.evidence_dir / "index.json"
        data = [
            {
                "id": e.id, "finding_id": e.finding_id,
                "source_tool": e.source_tool, "type": e.evidence_type,
                "description": e.description, "filepath": e.filepath,
                "timestamp": e.timestamp,
            }
            for e in self.evidence
        ]
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        return str(filepath)
