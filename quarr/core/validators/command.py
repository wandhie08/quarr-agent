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
    for arg in argv:
        validate_arg(arg)
    return argv
