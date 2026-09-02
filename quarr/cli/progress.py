"""
progress.py - CLI progress indicators (Phase 6).

Wraps rich spinners/progress. `status` matches the agent's async
status_callback signature so live updates render in place.
"""

from contextlib import contextmanager


class ProgressReporter:
    def __init__(self, renderer=None):
        self.renderer = renderer
        try:
            from rich.console import Console

            self._console = Console()
            self._rich = True
        except ImportError:
            self._console = None
            self._rich = False

    async def status(self, message: str) -> None:
        """Async status callback (matches QuarrAgent status_callback)."""
        if self._rich:
            self._console.print(message, style="dim")
        else:
            print(message)

    @contextmanager
    def spinner(self, label: str):
        if self._rich:
            with self._console.status(label):
                yield
        else:
            print(f"... {label}")
            yield

    def plan_progress(self, step: int, total: int) -> str:
        return f"Step {step}/{total}"
