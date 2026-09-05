"""
cvss.py - CVSS v3.1 base score calculator.

Computes the CVSS v3.1 Base Score from a vector string per the official spec
(FIRST.org CVSS v3.1). Used to attach precise, defensible severity scores to
findings in bug-bounty / professional reports.
"""

from __future__ import annotations

import math

# Metric value weights (CVSS v3.1 spec).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}       # Attack Vector
_AC = {"L": 0.77, "H": 0.44}                            # Attack Complexity
_PR = {"N": 0.85, "L": 0.62, "H": 0.27}                 # Privileges Required (Scope Unchanged)
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}                # Privileges Required (Scope Changed)
_UI = {"N": 0.85, "R": 0.62}                            # User Interaction
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}                 # Confidentiality/Integrity/Availability


def _roundup(x: float) -> float:
    """CVSS v3.1 Appendix A roundup: 1-decimal ceil on int-scaled value."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    """Parse a CVSS v3.1 vector string into a metric dict. Raises ValueError."""
    v = (vector or "").strip()
    parts = v.split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]
    metrics = {}
    for p in parts:
        if ":" in p:
            k, val = p.split(":", 1)
            metrics[k.strip().upper()] = val.strip().upper()
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    for r in required:
        if r not in metrics:
            raise ValueError(f"Missing CVSS metric: {r}")
    return metrics


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 Base Score (0.0–10.0) for a vector string."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = _PR_C[m["PR"]] if scope_changed else _PR[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_of(score: float) -> str:
    """Map a base score to the CVSS v3.1 qualitative severity rating."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# Default vectors per common vulnerability class — a reasonable starting point
# when only the finding type is known (operator should refine per target).
_DEFAULT_VECTORS = {
    "sql-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H",
    "rce": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "command-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "bola": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:H/A:N",
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:N/A:N",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:N/C:H/I:N/A:N",
    "excessive-data-exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
    "hardcoded-secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
    "weak-credentials": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:H",
    "jwt-weakness": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:H/A:N",
    "insecure-config": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:L/I:N/A:N",
    "info-disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:L/I:N/A:N",
    "path-traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:N/C:H/I:N/A:N",
}


def suggest_vector(vuln_type: str) -> str | None:
    """Return a default CVSS vector for a coarse vuln-type label, or None."""
    return _DEFAULT_VECTORS.get((vuln_type or "").strip().lower())


def score_finding(vuln_type: str = "", vector: str = "") -> dict:
    """Compute CVSS for a finding.

    If `vector` is given, score it. Otherwise use the default vector for
    `vuln_type`. Returns {'score', 'severity', 'vector'} or empty dict if
    nothing usable.
    """
    v = vector or suggest_vector(vuln_type) or ""
    if not v:
        return {}
    try:
        score = base_score(v)
    except ValueError:
        return {}
    return {"score": score, "severity": severity_of(score), "vector": v}
