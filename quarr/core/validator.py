"""
validator.py - M4: Finding Validation Engine

State machine untuk finding lifecycle:

    OBSERVATION → HYPOTHESIS → DETECTED → VALIDATING → CONFIRMED / DISMISSED → REPORTED

Setiap transisi memerlukan evidence atau justification.
Agent tidak bisa langsung jump dari observation ke confirmed.
"""

import logging

from quarr.core.models import Finding, FindingStatus, PentestState
from quarr.knowledge.base import get_cwe_for_finding

logger = logging.getLogger("quarr.validator")


# === Allowed Transitions ===

VALID_TRANSITIONS = {
    FindingStatus.OBSERVATION: [FindingStatus.HYPOTHESIS, FindingStatus.DISMISSED],
    FindingStatus.HYPOTHESIS: [FindingStatus.DETECTED, FindingStatus.DISMISSED],
    FindingStatus.DETECTED: [FindingStatus.VALIDATING, FindingStatus.DISMISSED],
    FindingStatus.VALIDATING: [FindingStatus.CONFIRMED, FindingStatus.DISMISSED],
    FindingStatus.CONFIRMED: [FindingStatus.REPORTED],
    FindingStatus.DISMISSED: [],  # terminal
    FindingStatus.REPORTED: [],   # terminal
}


class FindingValidator:
    """
    Manages finding lifecycle transitions.

    Rules:
    1. Each transition requires justification
    2. Cannot skip states (obs → confirmed is invalid)
    3. Confidence increases with each validation step
    4. CWE and CVSS are auto-enriched on confirmation
    """

    @staticmethod
    def can_transition(current: FindingStatus, target: FindingStatus) -> bool:
        allowed = VALID_TRANSITIONS.get(current, [])
        return target in allowed

    @staticmethod
    def transition(
        finding: Finding,
        new_status: FindingStatus,
        justification: str = "",
        evidence: str | None = None,
    ) -> bool:
        """
        Transition a finding to new status.

        Returns True if successful, False if invalid transition.
        """
        if not FindingValidator.can_transition(finding.status, new_status):
            logger.warning(
                f"Invalid transition: {finding.id} "
                f"{finding.status.value} → {new_status.value}"
            )
            return False

        old_status = finding.status
        finding.status = new_status

        if evidence:
            finding.evidence.append(evidence)

        # Adjust confidence based on transition
        if new_status == FindingStatus.HYPOTHESIS:
            finding.confidence = max(finding.confidence, 0.3)
        elif new_status == FindingStatus.DETECTED:
            finding.confidence = max(finding.confidence, 0.5)
        elif new_status == FindingStatus.VALIDATING:
            finding.confidence = max(finding.confidence, 0.7)
        elif new_status == FindingStatus.CONFIRMED:
            finding.confidence = max(finding.confidence, 0.9)
            # Auto-enrich with CWE
            cwe = get_cwe_for_finding(finding.title)
            if cwe and cwe["id"] not in finding.references:
                finding.references.append(cwe["id"])
                if not finding.remediation:
                    finding.remediation = cwe["remediation"]
        elif new_status == FindingStatus.DISMISSED:
            finding.confidence = 0.0

        logger.info(
            f"Finding {finding.id}: {old_status.value} → {new_status.value} "
            f"(confidence: {finding.confidence}) "
            f"reason: {justification}"
        )
        return True

    @staticmethod
    def auto_validate_findings(state: PentestState) -> list[str]:
        """
        Auto-advance findings yang punya cukup evidence.

        Rules:
        - DETECTED + multiple evidence sources → VALIDATING
        - VALIDATING + tool confirms exploit → CONFIRMED
        - DETECTED + no corroborating evidence after all tools run → stays

        Returns list of actions taken.
        """
        actions = []

        for finding in state.findings:
            # Skip terminal states
            if finding.status in (
                FindingStatus.CONFIRMED,
                FindingStatus.DISMISSED,
                FindingStatus.REPORTED,
            ):
                continue

            evidence_count = len(finding.evidence)
            related_obs = [
                o for o in state.observations
                if finding.asset in o.description
                or finding.title.lower().split()[0] in o.description.lower()
            ]

            # OBSERVATION → HYPOTHESIS (jika ada tool yang mendeteksi)
            if finding.status == FindingStatus.OBSERVATION:
                if related_obs:
                    FindingValidator.transition(
                        finding,
                        FindingStatus.HYPOTHESIS,
                        justification=f"Corroborated by {len(related_obs)} observation(s)",
                    )
                    actions.append(f"{finding.id}: observation → hypothesis")

            # HYPOTHESIS → DETECTED (jika scanner mendeteksi)
            elif finding.status == FindingStatus.HYPOTHESIS:
                scanner_tools = ["vulnerability_scan", "sqli_scan", "xss_scan",
                                 "command_injection_scan", "web_vuln_scan"]
                scanner_obs = [
                    o for o in related_obs
                    if o.source_tool in scanner_tools
                ]
                if scanner_obs:
                    FindingValidator.transition(
                        finding,
                        FindingStatus.DETECTED,
                        justification=f"Detected by {scanner_obs[0].source_tool}",
                        evidence=scanner_obs[0].description,
                    )
                    actions.append(f"{finding.id}: hypothesis → detected")

            # DETECTED → VALIDATING (jika ada multiple evidence)
            elif finding.status == FindingStatus.DETECTED:
                if evidence_count >= 2 or finding.confidence >= 0.8:
                    FindingValidator.transition(
                        finding,
                        FindingStatus.VALIDATING,
                        justification=f"{evidence_count} evidence items, confidence {finding.confidence}",
                    )
                    actions.append(f"{finding.id}: detected → validating")

            # VALIDATING → CONFIRMED (jika high confidence + evidence)
            elif finding.status == FindingStatus.VALIDATING:
                if finding.confidence >= 0.85 and evidence_count >= 2:
                    FindingValidator.transition(
                        finding,
                        FindingStatus.CONFIRMED,
                        justification="Sufficient evidence for confirmation",
                    )
                    actions.append(f"{finding.id}: validating → confirmed")

        return actions

    @staticmethod
    def promote_to_reported(finding: Finding) -> bool:
        """Mark a confirmed finding as reported."""
        if finding.status != FindingStatus.CONFIRMED:
            return False
        return FindingValidator.transition(
            finding, FindingStatus.REPORTED,
            justification="Included in assessment report"
        )
