"""
command.py - Command argument sanitization (Phase 4).

Operates on argument vectors (lists) only — never reconstructs a shell string.
Blocks shell metacharacters so LLM/user values cannot inject commands.
"""

import re

from quarr.core.exceptions import ArgumentValidationError

# Arguments are executed with shell=False (argv vectors, never a shell string),
# so characters that are only dangerous to a shell are harmless inside a single
# argv element. We therefore ALLOW URL characters (? & # ~ [ ]) — required for
# realistic targets like http://site/page?id=1&x=2 which SQLi/nuclei/web tools
# need — while still blocking the genuinely dangerous shell metacharacters
# (; | $ ` < > and newlines) as defense-in-depth.
ARG_SAFE = re.compile(r"^[A-Za-z0-9._:/@=,\-\+%?&#~\[\]]+$")
DANGEROUS = set(";|$`><\n\r")


def validate_arg(arg: str) -> str:
    if not isinstance(arg, str) or arg == "":
        raise ArgumentValidationError("Empty or non-string argument")
    if any(c in DANGEROUS for c in arg):
        raise ArgumentValidationError(
            "Argument contains shell metacharacters", context={"argument": arg}
        )
    if not ARG_SAFE.match(arg):
        raise ArgumentValidationError(
            "Argument failed allowlist validation", context={"argument": arg}
        )
    return arg


def validate_argv(argv: list) -> list:
    if not argv:
        raise ArgumentValidationError("Empty argument vector")
    # Flags whose FOLLOWING value is an HTTP header/cookie string (may contain
    # spaces). Such a value is validated with the header validator; everything
    # else uses the strict arg validator.
    header_flags = {"-H", "--header", "--headers", "-b", "--cookie", "--cookies", "-id"}
    expect_header_value = False
    for arg in argv:
        if expect_header_value:
            validate_header_arg(arg)
            expect_header_value = False
            continue
        validate_arg(arg)
        if arg in header_flags:
            expect_header_value = True
    return argv


# HTTP header / cookie values legitimately contain spaces and a wider charset
# (e.g. "Authorization: Bearer <jwt>", "session=abc; role=user"). They are still
# passed as a SINGLE argv element under shell=False, so a space is harmless —
# but we must still block the genuinely dangerous shell metacharacters as
# defense-in-depth. This validator is for header/cookie args only.
_HEADER_SAFE = re.compile(r"^[A-Za-z0-9 _.:/@=,\-\+%?&#~\[\]{}\"';*]+$")
_HEADER_DANGEROUS = set("|$`><\n\r")


def validate_header_arg(value: str) -> str:
    """Validate an HTTP header/cookie value for safe argv (shell=False) passthrough.

    Allows spaces and typical header punctuation; rejects shell metacharacters
    that could matter if the value ever reached a shell. Use only for values
    passed to tools that accept a header/cookie flag (sqlmap --headers/--cookie,
    nikto, etc.).
    """
    if not isinstance(value, str) or value == "":
        raise ArgumentValidationError("Empty or non-string header value")
    if any(c in _HEADER_DANGEROUS for c in value):
        raise ArgumentValidationError(
            "Header value contains shell metacharacters", context={"argument": value[:60]}
        )
    if not _HEADER_SAFE.match(value):
        raise ArgumentValidationError(
            "Header value failed allowlist validation", context={"argument": value[:60]}
        )
    return value
