"""
dedup.py - Finding deduplication (Phase 5).

Merges duplicate findings by normalized (title, asset, CWE), combining evidence
and keeping the highest severity and confidence. Idempotent; supports dry-run.
"""

import re
from dataclasses import dataclass, field

from quarr.core.models import Severity

_SEV_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class DedupReport:
    merged: int = 0
    groups: list[list] = field(default_factory=list)


def _norm_title(title: str) -> str:
    return re.sub(r"\s+", " ", (title or "").strip().lower())


def _key(finding):
    cwe = None
    for ref in getattr(finding, "references", []) or []:
        if "CWE" in ref.upper():
            cwe = ref
            break
    return (_norm_title(finding.title), finding.asset, cwe)


def deduplicate(state, *, dry_run: bool = False) -> DedupReport:
    groups = {}
    order = []
    for f in state.findings:
        k = _key(f)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)

    report = DedupReport()
    merged_findings = []
    for k in order:
        members = groups[k]
        if len(members) == 1:
            merged_findings.append(members[0])
            continue

        report.groups.append([f.id for f in members])
        report.merged += len(members) - 1

        # Keep the member with the highest severity as the primary.
        primary = max(members, key=lambda f: (_SEV_ORDER.get(f.severity, 0), f.confidence))
        for other in members:
            if other is primary:
                continue
            for ev in other.evidence:
                if ev not in primary.evidence:
                    primary.evidence.append(ev)
            for oid in other.observation_ids:
                if oid not in primary.observation_ids:
                    primary.observation_ids.append(oid)
            primary.confidence = max(primary.confidence, other.confidence)
        merged_findings.append(primary)

    if not dry_run:
        state.findings = merged_findings
    return report
