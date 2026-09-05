"""
evidence.py - M17: Evidence Collector

Structured evidence collection untuk findings.
Setiap evidence punya: timestamp, source, type, content, finding_id.
"""

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


def _custody_key() -> bytes | None:
    """Return the HMAC key used to sign the evidence index, or None.

    The key MUST live outside the evidence bundle so an attacker who tampers
    with evidence files cannot forge the signature. Sources, in order:
      1. QUARR_CUSTODY_KEY env var
      2. ~/.quarr/custody.key (created 0600 on first use)
    """
    env = os.environ.get("QUARR_CUSTODY_KEY")
    if env:
        return env.encode()
    key_path = Path(os.environ.get("QUARR_CUSTODY_KEY_FILE",
                                   os.path.expanduser("~/.quarr/custody.key")))
    try:
        if key_path.exists():
            data = key_path.read_bytes().strip()
            return data or None
        key_path.parent.mkdir(parents=True, exist_ok=True)
        new_key = os.urandom(32).hex().encode()
        # Write atomically with restrictive permissions.
        fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(new_key)
        return new_key
    except OSError:
        return None


@dataclass
class Evidence:
    id: str
    finding_id: str
    source_tool: str
    evidence_type: str  # "tool_output", "screenshot", "request_response", "file", "note"
    description: str
    content: str = ""
    filepath: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    sha256: str = ""
    collector: str = "quarr"
    custody: list = field(default_factory=list)


class EvidenceCollector:
    """Manage evidence for an engagement."""

    def __init__(self, engagement_id: str, base_dir: str = "engagements"):
        self.engagement_id = engagement_id
        self.evidence_dir = Path(base_dir) / engagement_id / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.evidence: list[Evidence] = []
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

        # Chain of custody: hash the stored file content + record acquisition.
        with open(filepath, "rb") as fh:
            ev.sha256 = hashlib.sha256(fh.read()).hexdigest()
        ev.custody.append({"event": "acquired", "ts": ev.timestamp, "by": ev.collector})

        self.evidence.append(ev)
        return ev

    def verify_chain(self) -> list:
        """Recompute each evidence file hash and flag mismatches (tampering)."""
        results = []
        for ev in self.evidence:
            entry = {"id": ev.id, "expected": ev.sha256, "actual": None, "ok": False}
            if ev.filepath and os.path.exists(ev.filepath):
                with open(ev.filepath, "rb") as fh:
                    entry["actual"] = hashlib.sha256(fh.read()).hexdigest()
                entry["ok"] = entry["actual"] == ev.sha256
            results.append(entry)
        return results

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

    def get_for_finding(self, finding_id: str) -> list[Evidence]:
        return [e for e in self.evidence if e.finding_id == finding_id]

    def summary(self) -> str:
        if not self.evidence:
            return "No evidence collected"
        lines = [f"Evidence collected: {len(self.evidence)}"]
        for ev in self.evidence:
            lines.append(f"  {ev.id} [{ev.evidence_type}] {ev.description[:60]}")
        return "\n".join(lines)

    def save_index(self) -> str:
        """Save evidence index as JSON, plus an HMAC signature over its content.

        The signature (index.json.sig) is computed with a key held OUTSIDE the
        bundle (QUARR_CUSTODY_KEY / ~/.quarr/custody.key), so tampering with the
        index or any evidence hash is detectable via verify_index_signature().
        """
        filepath = self.evidence_dir / "index.json"
        data = [
            {
                "id": e.id,
                "finding_id": e.finding_id,
                "source_tool": e.source_tool,
                "type": e.evidence_type,
                "description": e.description,
                "filepath": e.filepath,
                "timestamp": e.timestamp,
                "sha256": e.sha256,
                "collector": e.collector,
                "custody": e.custody,
            }
            for e in self.evidence
        ]
        raw = json.dumps(data, indent=2)
        with open(filepath, "w") as f:
            f.write(raw)

        # Tamper-evident signature over the exact bytes of the index.
        key = _custody_key()
        if key is not None:
            sig = hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()
            with open(str(filepath) + ".sig", "w") as f:
                f.write(sig)
        return str(filepath)

    def verify_index_signature(self) -> dict:
        """Verify the index HMAC signature to detect tampering.

        Returns {'signed': bool, 'valid': bool, 'reason': str}. `valid` is True
        only if the signature matches the current index content under the
        out-of-bundle key — i.e. neither the index nor recorded hashes were
        altered.
        """
        filepath = self.evidence_dir / "index.json"
        sig_path = Path(str(filepath) + ".sig")
        if not filepath.exists():
            return {"signed": False, "valid": False, "reason": "no index"}
        if not sig_path.exists():
            return {"signed": False, "valid": False, "reason": "no signature file"}
        key = _custody_key()
        if key is None:
            return {"signed": True, "valid": False, "reason": "no custody key available"}
        raw = filepath.read_text()
        expected = hmac.new(key, raw.encode(), hashlib.sha256).hexdigest()
        actual = sig_path.read_text().strip()
        if hmac.compare_digest(expected, actual):
            return {"signed": True, "valid": True, "reason": "signature valid"}
        return {"signed": True, "valid": False, "reason": "SIGNATURE MISMATCH — index tampered"}
