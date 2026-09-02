"""
base.py - ToolIntegration Abstract Base

Common lifecycle for every external tool integration:
    check availability → build argument vector → execute → parse output.

Subclasses implement build_command() and parse_output() and declare
binary_name plus metadata. run() ties them together and returns a ToolResult.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from quarr.core.exceptions import QuarrError, ToolNotFoundError, ToolOutputParseError
from quarr.core.logging import get_logger
from quarr.core.models import RiskLevel
from quarr.tools.checker import ToolChecker
from quarr.tools.executor import SecureExecutor

logger = get_logger("quarr.tools.integration")


@dataclass
class ToolResult:
    tool_name: str
    success: bool
    raw_output: str
    parsed: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0
    error: str | None = None


class ToolIntegration(ABC):
    # Subclasses override these.
    binary_name: str = ""
    name: str = ""
    category: str = "misc"
    risk_level: RiskLevel = RiskLevel.LOW
    default_timeout: int = 180
    requires_scope: bool = True

    def __init__(self, executor: SecureExecutor | None = None):
        self._executor = executor or SecureExecutor()

    @abstractmethod
    def build_command(self, **kwargs) -> list[str]:
        """Return the argument vector for this tool invocation."""

    @abstractmethod
    def parse_output(self, raw: str) -> dict[str, Any]:
        """Parse raw tool output into a structured dict."""

    def is_available(self) -> bool:
        return ToolChecker.is_available(self.binary_name)

    def run(self, **kwargs) -> ToolResult:
        if not self.is_available():
            raise ToolNotFoundError(
                f"Tool not installed: {self.binary_name}",
                context={"tool": self.name or self.binary_name},
            )

        argv = self.build_command(**kwargs)
        try:
            res = self._executor.run(argv, self.default_timeout)
        except QuarrError:
            raise  # executor already raised a typed QuarrError

        try:
            parsed = self.parse_output(res.stdout)
        except ToolOutputParseError as e:
            logger.error("tool_output_parse_error", tool=self.name, **e.context)
            return ToolResult(
                tool_name=self.name or self.binary_name,
                success=False,
                raw_output=res.stdout,
                parsed={},
                duration_ms=res.duration_ms,
                error=str(e),
            )

        return ToolResult(
            tool_name=self.name or self.binary_name,
            success=True,
            raw_output=res.stdout,
            parsed=parsed,
            duration_ms=res.duration_ms,
        )
