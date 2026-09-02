"""
audit.py - Immutable Audit Logging

Writes newline-delimited JSON audit records to a dedicated, size-rotated file,
separate from application logs. Each record has a monotonic sequence number and
a SHA-256 integrity hash computed over the record (excluding the hash field).

Arguments and result summaries are redacted for secrets before being written.
Raw credentials/evidence are never stored here.
"""

import hashlib
import json
import logging
import logging.handlers
import os
from datetime import UTC, datetime
from typing import Any

from quarr.core.logging import DEFAULT_REDACT_KEYS

_REDACTED = "***REDACTED***"


def _redact(value: Any, keys: set) -> Any:
    if isinstance(value, dict):
        return {k: (_REDACTED if k.lower() in keys else _redact(v, keys)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact(v, keys) for v in value)
    return value


class AuditLogger:
    """Append-only, integrity-hashed audit trail for tool executions."""

    def __init__(
        self,
        path: str = "audit.log",
        rotate_max_bytes: int = 10_485_760,
        rotate_backups: int = 5,
        redact_keys: list | None = None,
    ):
        self.path = path
        self._redact_keys = {k.lower() for k in (redact_keys or DEFAULT_REDACT_KEYS)}
        self._sequence = self._seed_sequence()
        self._pending: dict[int, dict[str, Any]] = {}

        self._logger = logging.getLogger(f"quarr.audit.{id(self)}")
        self._logger.propagate = False
        self._logger.setLevel(logging.INFO)
        # Avoid duplicate handlers on re-init in the same process.
        self._logger.handlers.clear()
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=rotate_max_bytes, backupCount=rotate_backups
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._logger.addHandler(handler)

    def _seed_sequence(self) -> int:
        """Seed the sequence counter from the last line of an existing file."""
        if not os.path.exists(self.path):
            return 0
        last_seq = 0
        try:
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        last_seq = max(last_seq, int(entry.get("sequence", 0)))
                    except (json.JSONDecodeError, ValueError):
                        continue
        except OSError:
            return 0
        return last_seq

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def _write(self, entry: dict[str, Any]) -> None:
        canonical = json.dumps(entry, sort_keys=True, default=str)
        entry_with_hash = dict(entry)
        entry_with_hash["sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
        self._logger.info(json.dumps(entry_with_hash, default=str))

    def record_execution(
        self,
        *,
        tool_name: str,
        target: str | None,
        arguments: dict[str, Any],
        session_id: str = "",
        engagement_id: str = "",
    ) -> int:
        """Record the start of a tool execution. Returns the sequence number."""
        self._sequence += 1
        seq = self._sequence
        entry = {
            "sequence": seq,
            "timestamp": self._now(),
            "event": "tool_execution",
            "tool_name": tool_name,
            "target": target,
            "arguments": _redact(arguments, self._redact_keys),
            "session_id": session_id,
            "engagement_id": engagement_id,
        }
        self._pending[seq] = entry
        self._write(entry)
        return seq

    def record_result(
        self,
        *,
        seq: int,
        success: bool,
        duration_ms: int,
        result_summary: str = "",
    ) -> None:
        """Record the result of a previously started tool execution."""
        base = self._pending.pop(seq, {})
        summary = _redact({"s": result_summary}, self._redact_keys)["s"]
        entry = {
            "sequence": seq,
            "timestamp": self._now(),
            "event": "tool_result",
            "tool_name": base.get("tool_name"),
            "target": base.get("target"),
            "success": success,
            "duration_ms": duration_ms,
            "result_summary": summary,
        }
        self._write(entry)

    def record_approval(
        self,
        *,
        tool_name: str,
        target: str | None,
        decision: str,
    ) -> int:
        """Record an approval decision (used by Phase 4)."""
        self._sequence += 1
        seq = self._sequence
        entry = {
            "sequence": seq,
            "timestamp": self._now(),
            "event": "approval",
            "tool_name": tool_name,
            "target": target,
            "decision": decision,
        }
        self._write(entry)
        return seq
