"""
path.py - Path traversal protection (Phase 4).

Resolves paths to canonical absolute form (following symlinks) and verifies
containment within an allowlisted base directory.
"""

import os

from quarr.core.exceptions import ValidationError


def validate_within(path: str, base: str) -> str:
    if not path:
        raise ValidationError("Empty path")
    real = os.path.realpath(path)
    base_real = os.path.realpath(base)
    if real != base_real and not real.startswith(base_real + os.sep):
        raise ValidationError(
            "Path escapes the allowlisted base directory",
            context={"path": path, "base": base, "resolved": real},
        )
    return real


def safe_join(base: str, *parts: str) -> str:
    joined = os.path.join(base, *parts)
    return validate_within(joined, base)
