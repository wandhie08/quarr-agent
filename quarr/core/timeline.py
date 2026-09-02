"""
timeline.py - Timeline reconstruction (Phase 5).

Aggregates events from tool executions, findings, and evidence into a
chronological timeline. Reconstructable from a persisted PentestState.
"""

import json
from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass
class TimelineEvent:
    ts: str
    kind: str
    detail: str
    asset: str | None = None
    ref_id: str | None = None


def _iso(dt) -> str:
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def build_timeline(state, evidence=None) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    for t in state.tool_history:
        events.append(
            TimelineEvent(
                ts=_iso(t.timestamp),
                kind="tool_execution",
                detail=f"{t.tool_name} ({'ok' if t.success else 'fail'})",
                asset=t.arguments.get("target") if isinstance(t.arguments, dict) else None,
            )
        )

    for f in state.findings:
        events.append(
            TimelineEvent(
                ts=_iso(getattr(f, "timestamp", datetime.now())),
                kind="finding",
                detail=f"{f.severity.value}: {f.title}",
                asset=f.asset,
                ref_id=f.id,
            )
        )

    if evidence:
        for e in evidence:
            events.append(
                TimelineEvent(
                    ts=_iso(e.timestamp),
                    kind="evidence",
                    detail=e.description,
                    ref_id=e.id,
                )
            )

    events.sort(key=lambda e: e.ts)
    return events


def filter_events(events, *, since=None, until=None, kind=None, asset=None):
    out = events
    if kind:
        out = [e for e in out if e.kind == kind]
    if asset:
        out = [e for e in out if e.asset == asset]
    if since:
        out = [e for e in out if e.ts >= since]
    if until:
        out = [e for e in out if e.ts <= until]
    return out


def to_json(events) -> str:
    return json.dumps([asdict(e) for e in events], indent=2)


def to_text(events) -> str:
    return "\n".join(
        f"{e.ts}  [{e.kind}] {e.detail}" + (f" ({e.asset})" if e.asset else "") for e in events
    )
