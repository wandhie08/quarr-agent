"""
executor.py - Secure Subprocess Executor

Executes external tools using an argument vector with shell=False. Each argument
is validated against an allowlist pattern to block shell metacharacters, so
user- or LLM-supplied values cannot inject additional commands.
"""

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

from quarr.core.exceptions import (
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from quarr.core.logging import get_logger

logger = get_logger("quarr.tools.executor")

# Values/flags may contain these characters. Shell metacharacters are excluded.
ARG_ALLOWLIST = re.compile(r"^[A-Za-z0-9._:/@=,\-\+%]+$")


@dataclass
class ExecResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int


class SecureExecutor:
    """Runs a validated argument vector with shell=False."""

    def validate_argv(self, argv: list[str]) -> None:
        # Delegate to the Phase 4 command validator (single source of truth).
        from quarr.core.validators.command import validate_argv as _validate

        _validate(argv)

    def _minimal_env(self, overrides: dict[str, str] | None) -> dict[str, str]:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if overrides:
            env.update(overrides)
        return env

    def run(
        self,
        argv: list[str],
        timeout: int,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ExecResult:
        self.validate_argv(argv)

        binary = shutil.which(argv[0])
        if binary is None:
            raise ToolNotFoundError(
                f"Binary not found on PATH: {argv[0]}",
                context={"binary": argv[0]},
            )

        resolved = [binary] + argv[1:]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                resolved,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=self._minimal_env(env),
            )
        except subprocess.TimeoutExpired as e:
            raise ToolTimeoutError(
                "Tool execution timed out",
                context={"binary": argv[0], "timeout": timeout},
                cause=e,
            ) from e
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.info(
            "tool_executed", binary=argv[0], exit_code=proc.returncode, duration_ms=duration_ms
        )
        return ExecResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            exit_code=proc.returncode,
            duration_ms=duration_ms,
        )

    def run_checked(self, argv: list[str], timeout: int, **kwargs) -> ExecResult:
        """Like run(), but raises ToolExecutionError on non-zero exit."""
        result = self.run(argv, timeout, **kwargs)
        if result.exit_code != 0:
            raise ToolExecutionError(
                "Tool exited with non-zero status",
                context={
                    "binary": argv[0],
                    "exit_code": result.exit_code,
                    "stderr": result.stderr[:300],
                },
            )
        return result
