"""
checker.py - Tool Availability Checker

Detects whether external tool binaries are installed (resolvable on PATH),
caching results for the process lifetime and optionally capturing versions.
"""

import shutil
import subprocess

from quarr.core.logging import get_logger

logger = get_logger("quarr.tools.checker")


class ToolChecker:
    _cache: dict[str, bool] = {}
    _versions: dict[str, str | None] = {}

    @classmethod
    def is_available(cls, binary: str) -> bool:
        if binary not in cls._cache:
            available = shutil.which(binary) is not None
            cls._cache[binary] = available
            if not available:
                logger.warning("tool_unavailable", binary=binary)
        return cls._cache[binary]

    @classmethod
    def version(cls, binary: str) -> str | None:
        if binary in cls._versions:
            return cls._versions[binary]
        version = None
        if cls.is_available(binary):
            for flag in ("--version", "-V", "version"):
                try:
                    proc = subprocess.run([binary, flag], capture_output=True, text=True, timeout=5)
                    out = (proc.stdout or proc.stderr or "").strip()
                    if out:
                        version = out.splitlines()[0][:120]
                        break
                except (subprocess.SubprocessError, OSError):
                    continue
        cls._versions[binary] = version
        return version

    @classmethod
    def check_all(cls, binaries: list[str]) -> dict[str, bool]:
        return {b: cls.is_available(b) for b in binaries}

    @classmethod
    def report(cls, binaries: list[str]) -> str:
        results = cls.check_all(binaries)
        lines = ["Tool availability:"]
        for binary, ok in sorted(results.items()):
            mark = "✓" if ok else "✗"
            lines.append(f"  {mark} {binary}")
        return "\n".join(lines)

    @classmethod
    def clear_cache(cls) -> None:
        cls._cache.clear()
        cls._versions.clear()
