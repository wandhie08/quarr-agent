"""
policy.py - Policy Engine

Otorisasi setiap tool call sebelum eksekusi.
LLM tidak boleh bypass fungsi ini.
"""

import ipaddress
import re

from quarr.core.exceptions import PolicyViolationError
from quarr.core.models import Engagement

# Backward-compatible alias: existing code imports/catches `PolicyViolation`.
# It now subclasses QuarrError via PolicyViolationError.
PolicyViolation = PolicyViolationError


class PolicyEngine:
    """
    Memvalidasi setiap tool call terhadap engagement scope.

    Rules:
    1. Target harus ada di allowed_targets
    2. Target tidak boleh ada di excluded_targets
    3. Tool harus ada di allowed_operations
    4. High-risk tools memerlukan approval (future)
    """

    @staticmethod
    def normalize_target(target: str) -> str:
        """Bersihkan target string — extract hostname/IP saja."""
        target = target.strip()
        target = re.sub(r"^https?://", "", target)
        target = target.rstrip("/")
        # Remove path, query, fragment — ambil hostname/IP saja
        target = target.split("/")[0]
        target = target.split("?")[0]
        target = target.split("#")[0]
        # Remove port
        target = target.split(":")[0]
        return target

    @staticmethod
    def target_matches_scope(target: str, scope_entry: str) -> bool:
        """
        Cek apakah target cocok dengan satu entry di scope.

        Mendukung:
        - Exact IP match: 10.10.10.20
        - CIDR match: 10.10.10.0/24
        - Hostname exact match: target.lab.local
        - Wildcard domain: *.lab.local
        """
        target = PolicyEngine.normalize_target(target)
        scope_entry = scope_entry.strip()

        # Exact match
        if target == scope_entry:
            return True

        # CIDR match
        if "/" in scope_entry:
            try:
                network = ipaddress.ip_network(scope_entry, strict=False)
                target_ip = ipaddress.ip_address(target)
                return target_ip in network
            except ValueError:
                pass

        # Wildcard domain match: *.example.com
        if scope_entry.startswith("*."):
            domain_suffix = scope_entry[1:]  # .example.com
            if target.endswith(domain_suffix) or target == scope_entry[2:]:
                return True

        return False

    @staticmethod
    def target_in_scope(target: str, allowed: list[str]) -> bool:
        """Cek apakah target ada di allowed scope."""
        for entry in allowed:
            if PolicyEngine.target_matches_scope(target, entry):
                return True
        return False

    @staticmethod
    def target_is_excluded(target: str, excluded: list[str]) -> bool:
        """Cek apakah target ada di excluded list."""
        for entry in excluded:
            if PolicyEngine.target_matches_scope(target, entry):
                return True
        return False

    @staticmethod
    def authorize(
        tool_name: str,
        args: dict,
        engagement: Engagement,
        *,
        role: str = None,
        tool_risk=None,
        scope_limiter=None,
        approval=None,
        session=None,
    ) -> bool:
        """
        Validasi tool call terhadap engagement policy.

        Raises PolicyViolation jika tidak diizinkan.
        Returns True jika OK.

        Phase 4 additions (all optional, backward compatible):
        - role + tool_risk → permission check
        - scope_limiter → distinct-target / rate caps
        - approval + tool_risk → approval gate for HIGH/CRITICAL tools
        """
        from quarr.core import permissions as _perms

        target = args.get("target")

        # Phase 4.1: permission check (role vs tool risk)
        if role is not None and tool_risk is not None:
            _perms.check(role, tool_risk, tool_name)

        # 1. Cek apakah tool diizinkan
        if engagement.allowed_operations:
            if tool_name not in engagement.allowed_operations:
                raise PolicyViolation(
                    f"Tool '{tool_name}' is not in the allowed operations list. "
                    f"Allowed: {engagement.allowed_operations}",
                    context={"tool": tool_name, "reason": "operation_not_allowed"},
                )

        # 2. Cek scope jika tool memerlukan target
        target = args.get("target")
        if target:
            target_clean = PolicyEngine.normalize_target(target)

            # Cek excluded dulu (takes precedence)
            if PolicyEngine.target_is_excluded(target_clean, engagement.excluded_targets):
                raise PolicyViolation(
                    f"Target '{target_clean}' is explicitly EXCLUDED from scope.",
                    context={"target": target_clean, "reason": "excluded"},
                )

            # Cek apakah in scope
            if not PolicyEngine.target_in_scope(target_clean, engagement.allowed_targets):
                raise PolicyViolation(
                    f"Target '{target_clean}' is NOT in the authorized scope. "
                    f"Authorized targets: {engagement.allowed_targets}",
                    context={"target": target_clean, "reason": "out_of_scope"},
                )

        # Phase 4.9: scope limiter (distinct-target / rate caps)
        if scope_limiter is not None:
            scope_limiter.check(target, engagement, session)

        # Phase 4.10: approval gate for dangerous tools
        if approval is not None and tool_risk is not None:
            approval.gate(tool_name, target, tool_risk)

        return True
