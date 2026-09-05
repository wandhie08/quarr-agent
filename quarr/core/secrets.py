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

    # Key-value patterns: keep the key, mask the value. Covers every sensitive
    # key declared in REDACTION_KEYS (secret, token, credential(s), authorization,
    # api_key, password, aws_secret_access_key, ...) so the free-text scrubber
    # stays in sync with the declared key list.
    kv_keys = (
        r"password|passwd|pwd|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|"
        r"token|credentials?|authorization|api[_-]?key|apikey|"
        r"aws_secret_access_key|client[_-]?secret"
    )
    result = re.sub(
        rf"(?i)((?:{kv_keys})\s*[:=]\s*)(\S+)", rf"\1{_REDACTED}", result
    )
    # Authorization header carries "<scheme> <token>" (two tokens); mask the
    # whole value to end-of-line so the credential part isn't left exposed.
    result = re.sub(
        r"(?i)(authorization\s*[:=]\s*)\S.*", rf"\1{_REDACTED}", result
    )
    result = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{10,}", rf"\1{_REDACTED}", result)

    # Basic-auth credentials embedded in URLs: scheme://user:pass@host
    result = re.sub(
        r"(?i)([a-z][a-z0-9+.\-]*://)[^/\s:@]+:[^/\s:@]+@",
        rf"\1{_REDACTED}@",
        result,
    )

    # Standalone high-signal tokens.
    result = PATTERNS["aws_key"].sub(_REDACTED, result)
    result = PATTERNS["openai"].sub(_REDACTED, result)
    # GitHub personal/OAuth/app tokens.
    result = re.sub(r"gh[pousr]_[A-Za-z0-9]{20,}", _REDACTED, result)
    # Slack tokens.
    result = re.sub(r"xox[baprs]-[A-Za-z0-9\-]{10,}", _REDACTED, result)
    # JWT (header.payload.signature).
    result = re.sub(
        r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
        _REDACTED,
        result,
    )
    result = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        _REDACTED,
        result,
        flags=re.DOTALL,
    )
    return result
