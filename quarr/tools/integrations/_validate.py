"""
_validate.py - Lightweight input validation for integrations (Phase 2).

Phase 4 will replace these with the dedicated validators package. Until then,
these mirror the accepted-input behavior of registry._validate_* helpers.
"""

import re

from quarr.core.exceptions import ArgumentValidationError, TargetValidationError

_TARGET_RE = re.compile(r"^[A-Za-z0-9._\-/]+$")


def validate_target(target: str) -> str:
    target = (target or "").strip()
    target = re.sub(r"^https?://", "", target)
    target = target.rstrip("/")
    if not _TARGET_RE.match(target):
        raise TargetValidationError("Invalid target format", context={"target": target})
    return target


def validate_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ArgumentValidationError("Empty URL")
    if not re.match(r"^https?://", url):
        url = f"https://{url}"
    # Reject spaces/metacharacters in the URL.
    if re.search(r"[\s;|&`$><]", url):
        raise ArgumentValidationError("URL contains invalid characters", context={"url": url})
    return url


def validate_ports(ports: str) -> str:
    ports = (ports or "").strip()
    if not re.match(r"^[0-9,\-]+$", ports):
        raise ArgumentValidationError("Invalid port specification", context={"ports": ports})
    return ports


# Directories from which wordlists/hashfiles may be read.
DEFAULT_ALLOWED_DIRS = ("/usr/share/wordlists", "/usr/share/seclists", "engagements")


def validate_file_path(path: str, allowed_dirs=DEFAULT_ALLOWED_DIRS) -> str:
    """Ensure a file path resolves within an allowlisted directory (no traversal)."""
    import os

    if not path:
        raise ArgumentValidationError("Empty file path")
    real = os.path.realpath(path)
    for base in allowed_dirs:
        base_real = os.path.realpath(base)
        if real == base_real or real.startswith(base_real + os.sep):
            return real
    raise ArgumentValidationError(
        "File path is outside allowlisted directories",
        context={"path": path, "allowed": list(allowed_dirs)},
    )


# Redact common credential patterns from tool output summaries.
_CRED_PATTERNS = [
    re.compile(r"(password:\s*)(\S+)", re.IGNORECASE),
    re.compile(r"(login:\s*\S+\s+password:\s*)(\S+)", re.IGNORECASE),
]


def redact_secrets(text: str) -> str:
    if not text:
        return text
    redacted = text
    # Redact "password: <value>" occurrences.
    redacted = re.sub(r"(?i)(password:\s*)(\S+)", r"\1***REDACTED***", redacted)
    return redacted
