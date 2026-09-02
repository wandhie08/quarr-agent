"""
secrets.py - Secrets detection and redaction (Phase 4).

Detects common credential patterns in text and redacts them. Provides the
canonical redaction key list consumed by logging and audit.
"""

import re
from dataclasses import dataclass

PATTERNS = {
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "openai": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "bearer": re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "password_kv": re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*(\S+)"),
    "generic_api": re.compile(r"(?i)api[_-]?key\s*[:=]\s*(\S+)"),
}

REDACTION_KEYS = [
    "api_key",
    "apikey",
    "authorization",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "credential",
    "credentials",
    "openai_api_key",
]

_REDACTED = "***REDACTED***"


@dataclass
class Secret:
    kind: str
    start: int
    end: int


def detect(text: str) -> list:
    if not text:
        return []
    found = []
    for kind, pat in PATTERNS.items():
        for m in pat.finditer(text):
            found.append(Secret(kind=kind, start=m.start(), end=m.end()))
    return found


def redact(text: str) -> str:
    if not text:
        return text
    result = text
    # Key-value patterns: keep the key, mask the value.
    result = re.sub(r"(?i)((?:password|passwd|pwd)\s*[:=]\s*)(\S+)", rf"\1{_REDACTED}", result)
    result = re.sub(r"(?i)(api[_-]?key\s*[:=]\s*)(\S+)", rf"\1{_REDACTED}", result)
    result = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{10,}", rf"\1{_REDACTED}", result)
    # Standalone tokens.
    result = PATTERNS["aws_key"].sub(_REDACTED, result)
    result = PATTERNS["openai"].sub(_REDACTED, result)
    result = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        _REDACTED,
        result,
        flags=re.DOTALL,
    )
    return result
