"""
learned.py - Cross-engagement learning layer (persistent knowledge).

Unlike quarr/knowledge/base.py (a static RAG catalog of OWASP/CWE/MITRE), this
module lets QUARR *accumulate* knowledge from the engagements it actually runs:

  1. Finding patterns  — "on <technology>, <tool> confirmed a <vuln-type>"
  2. Tool effectiveness — success/attempt counts per (technology, tool)

Confirmed findings and successful tool runs are recorded to a persistent JSON
store. At the start of a later engagement, relevant learned hints are retrieved
and injected into the LLM context, so the agent becomes more targeted over time
(e.g. after learning that Werkzeug APIs often expose `/_debug`, it prioritizes
that check on the next Flask target).

Storage is a single JSON file under a user data dir, written atomically, size-
bounded, and deduplicated. It contains NO secrets — only vuln types, tool names,
technology labels, and short titles.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

# Default store location (overridable via env for tests / custom deployments).
_DEFAULT_DIR = os.environ.get(
    "QUARR_LEARN_DIR", os.path.expanduser("~/.quarr")
)
_STORE_NAME = "learned_knowledge.json"

# Bounds to keep the store small and relevant.
_MAX_PATTERNS = 500
_MAX_HINTS_RETURNED = 6


def _store_path() -> Path:
    return Path(_DEFAULT_DIR) / _STORE_NAME


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _norm(text: str) -> str:
    return (text or "").strip().lower()


def _empty_store() -> dict:
    return {"version": 1, "finding_patterns": [], "tool_effectiveness": {}}


def load_store() -> dict:
    """Load the learned-knowledge store, or a fresh empty one."""
    p = _store_path()
    if not p.exists():
        return _empty_store()
    try:
        with open(p) as f:
            data = json.load(f)
        if not isinstance(data, dict) or "finding_patterns" not in data:
            return _empty_store()
        data.setdefault("tool_effectiveness", {})
        data.setdefault("finding_patterns", [])
        return data
    except (json.JSONDecodeError, ValueError, OSError):
        # A corrupt store must never crash an engagement — start fresh.
        return _empty_store()


def _save_store(data: dict) -> None:
    """Atomically write the store (temp file + replace)."""
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Bound the pattern list (keep the most recent).
    if len(data.get("finding_patterns", [])) > _MAX_PATTERNS:
        data["finding_patterns"] = data["finding_patterns"][-_MAX_PATTERNS:]
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, p)
    except OSError:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _pattern_key(technology: str, vuln_type: str, tool: str) -> tuple:
    return (_norm(technology), _norm(vuln_type), _norm(tool))


def record_finding(technology: str, vuln_type: str, tool: str, title: str = "") -> None:
    """Record a confirmed finding pattern: on `technology`, `tool` found `vuln_type`.

    Deduplicated on (technology, vuln_type, tool); repeat sightings bump a count
    and refresh the timestamp so common patterns rank higher.
    """
    technology, vuln_type, tool = (technology or "").strip(), (vuln_type or "").strip(), (tool or "").strip()
    if not (technology and vuln_type):
        return
    data = load_store()
    key = _pattern_key(technology, vuln_type, tool)
    for pat in data["finding_patterns"]:
        if _pattern_key(pat.get("technology", ""), pat.get("vuln_type", ""), pat.get("tool", "")) == key:
            pat["count"] = pat.get("count", 1) + 1
            pat["last_seen"] = _now()
            if title and title not in pat.get("titles", []):
                pat.setdefault("titles", []).append(title[:120])
            _save_store(data)
            return
    data["finding_patterns"].append({
        "technology": technology,
        "vuln_type": vuln_type,
        "tool": tool,
        "titles": [title[:120]] if title else [],
        "count": 1,
        "last_seen": _now(),
    })
    _save_store(data)


def record_tool_result(technology: str, tool: str, success: bool) -> None:
    """Record a tool outcome against a technology to build effectiveness stats."""
    technology, tool = (technology or "").strip(), (tool or "").strip()
    if not (technology and tool):
        return
    data = load_store()
    eff = data["tool_effectiveness"]
    tech_key = _norm(technology)
    bucket = eff.setdefault(tech_key, {})
    stat = bucket.setdefault(tool, {"success": 0, "attempts": 0})
    stat["attempts"] += 1
    if success:
        stat["success"] += 1
    _save_store(data)


def record_from_state(state) -> int:
    """Learn from a completed engagement's state.

    Records a pattern for every CONFIRMED finding (mapping it to the technologies
    discovered on its asset) and tool effectiveness for every tool run. Returns
    the number of finding patterns recorded.
    """
    from quarr.core.models import FindingStatus

    # Map asset -> technologies discovered on it.
    tech_by_asset = defaultdict(list)
    all_techs = []
    for h in state.hosts:
        for s in h.services:
            if s.product:
                tech_by_asset[h.address].append(s.product)
                all_techs.append(s.product)

    recorded = 0
    for f in state.findings:
        if f.status != FindingStatus.CONFIRMED:
            continue
        vuln_type = _vuln_type_from_title(f.title)
        # Which tool produced it? Best-effort: the last tool in history, else "".
        tool = state.tool_history[-1].tool_name if state.tool_history else ""
        techs = tech_by_asset.get(f.asset) or all_techs or ["generic"]
        for tech in set(techs):
            record_finding(tech, vuln_type, tool, title=f.title)
            recorded += 1

    # Tool effectiveness across the engagement.
    techs_for_tools = set(all_techs) or {"generic"}
    for t in state.tool_history:
        for tech in techs_for_tools:
            record_tool_result(tech, t.tool_name, t.success)

    return recorded


def _vuln_type_from_title(title: str) -> str:
    """Map a finding title to a coarse vuln-type label for reuse."""
    t = _norm(title)
    mapping = [
        ("sql injection", "sql-injection"), ("sqli", "sql-injection"),
        ("xss", "xss"), ("cross-site scripting", "xss"),
        ("command injection", "command-injection"), ("rce", "rce"),
        ("bola", "bola"), ("object level", "bola"), ("idor", "bola"),
        ("excessive data", "excessive-data-exposure"),
        ("hardcoded secret", "hardcoded-secret"), ("secret", "hardcoded-secret"),
        ("debuggable", "insecure-config"), ("cleartext", "insecure-config"),
        ("weak credential", "weak-credentials"), ("default login", "weak-credentials"),
        ("path traversal", "path-traversal"), ("directory listing", "info-disclosure"),
        ("jwt", "jwt-weakness"),
    ]
    for needle, label in mapping:
        if needle in t:
            return label
    # Fallback: first word.
    return t.split()[0] if t else "unknown"


def get_hints(technologies: list[str] | None = None, query: str = "") -> str:
    """Retrieve learned hints relevant to the given technologies / objective.

    Returns a formatted string for LLM-context injection, or "" if nothing
    relevant has been learned yet.
    """
    data = load_store()
    patterns = data.get("finding_patterns", [])
    if not patterns:
        return ""

    techs = {_norm(t) for t in (technologies or []) if t}
    q = _norm(query)

    scored = []
    for pat in patterns:
        ptech = _norm(pat.get("technology", ""))
        score = pat.get("count", 1)
        relevant = False
        if techs and any(ptech in t or t in ptech for t in techs):
            relevant = True
            score += 5
        if q and (ptech in q or pat.get("vuln_type", "") in q):
            relevant = True
            score += 2
        # With no context filters, surface the globally most-common patterns.
        if not techs and not q:
            relevant = True
        if relevant:
            scored.append((score, pat))

    if not scored:
        return ""
    scored.sort(key=lambda x: x[0], reverse=True)
    top = [p for _, p in scored[:_MAX_HINTS_RETURNED]]

    eff = data.get("tool_effectiveness", {})
    lines = ["LEARNED KNOWLEDGE (from previous engagements):"]
    for pat in top:
        tech = pat.get("technology", "?")
        vt = pat.get("vuln_type", "?")
        tool = pat.get("tool", "")
        seen = pat.get("count", 1)
        hint = f"  • On {tech}: previously confirmed {vt}"
        if tool:
            hint += f" (via {tool})"
        hint += f" — seen {seen}x."
        lines.append(hint)
        # Attach the best tool for this technology if we have stats.
        tech_stats = eff.get(_norm(tech), {})
        best = _best_tool(tech_stats)
        if best:
            lines.append(f"    ↳ Most effective tool on {tech}: {best}")
    lines.append("Prioritize these checks/tools where applicable.")
    return "\n".join(lines)


def _best_tool(tech_stats: dict) -> str:
    best_name, best_rate, best_attempts = "", -1.0, 0
    for tool, stat in tech_stats.items():
        attempts = stat.get("attempts", 0)
        if attempts == 0:
            continue
        rate = stat.get("success", 0) / attempts
        if rate > best_rate or (rate == best_rate and attempts > best_attempts):
            best_name, best_rate, best_attempts = tool, rate, attempts
    if best_name and best_attempts >= 1:
        return f"{best_name} ({best_rate:.0%} success over {best_attempts})"
    return ""


def summary() -> str:
    """Human-readable summary of what QUARR has learned so far."""
    data = load_store()
    pats = data.get("finding_patterns", [])
    eff = data.get("tool_effectiveness", {})
    lines = [
        "=== QUARR LEARNED KNOWLEDGE ===",
        f"Finding patterns: {len(pats)}",
        f"Technologies with tool stats: {len(eff)}",
    ]
    for pat in sorted(pats, key=lambda p: p.get("count", 1), reverse=True)[:10]:
        lines.append(
            f"  [{pat.get('count',1)}x] {pat.get('technology')}: "
            f"{pat.get('vuln_type')} via {pat.get('tool') or '?'}"
        )
    return "\n".join(lines)


def reset_store() -> None:
    """Delete the learned-knowledge store (mainly for tests)."""
    p = _store_path()
    if p.exists():
        p.unlink()
