"""
render.py - CLI rendering (Phase 6).

Provides a Renderer with a rich-based implementation and a plain-text fallback
so the CLI degrades gracefully when `rich` is unavailable.
"""

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class PlainRenderer:
    """Plain-text renderer (fallback / non-TTY)."""

    def findings_table(self, state) -> None:
        if not state.findings:
            print("No findings yet.")
            return
        for f in state.findings:
            print(
                f"[{f.severity.value.upper()}] {f.title} | {f.asset} | "
                f"{f.status.value} | conf={f.confidence}"
            )

    def state_panel(self, state) -> None:
        print(state.summary())

    def scope_panel(self, engagement) -> None:
        print(f"Engagement: {engagement.name}")
        print(f"Scope: {', '.join(engagement.allowed_targets)}")
        if engagement.excluded_targets:
            print(f"Excluded: {', '.join(engagement.excluded_targets)}")

    def history_table(self, state) -> None:
        if not state.tool_history:
            print("No tool executions yet.")
            return
        for t in state.tool_history:
            mark = "OK" if t.success else "FAIL"
            print(f"[{mark}] {t.tool_name}({t.arguments}) " f"{t.timestamp.strftime('%H:%M:%S')}")

    def sessions_table(self, sessions) -> None:
        if not sessions:
            print("No saved sessions.")
            return
        for s in sessions:
            print(f"[{s['id']}] {s['name']} — {s['findings']} findings")

    def result_panel(self, text: str) -> None:
        print(text)

    def info(self, text: str) -> None:
        print(text)


class RichRenderer:
    """Styled renderer using the `rich` library."""

    def __init__(self):
        from rich.console import Console

        self.console = Console()

    def _sev(self, sev: str) -> str:
        style = SEVERITY_STYLE.get(sev, "white")
        return f"[{style}]{sev.upper()}[/]"

    def findings_table(self, state) -> None:
        from rich.table import Table

        if not state.findings:
            self.console.print("No findings yet.", style="dim")
            return
        table = Table(title="Findings")
        for col in ("Severity", "Title", "Asset", "Status", "Conf"):
            table.add_column(col)
        for f in state.findings:
            table.add_row(
                self._sev(f.severity.value), f.title, f.asset, f.status.value, str(f.confidence)
            )
        self.console.print(table)

    def state_panel(self, state) -> None:
        from rich.panel import Panel

        self.console.print(Panel(state.summary(), title="Assessment State"))

    def scope_panel(self, engagement) -> None:
        from rich.panel import Panel

        body = f"[bold]{engagement.name}[/]\nScope: {', '.join(engagement.allowed_targets)}"
        if engagement.excluded_targets:
            body += f"\nExcluded: {', '.join(engagement.excluded_targets)}"
        self.console.print(Panel(body, title="Engagement"))

    def history_table(self, state) -> None:
        from rich.table import Table

        if not state.tool_history:
            self.console.print("No tool executions yet.", style="dim")
            return
        table = Table(title="Tool History")
        for col in ("", "Tool", "Arguments", "Time"):
            table.add_column(col)
        for t in state.tool_history:
            mark = "[green]OK[/]" if t.success else "[red]FAIL[/]"
            table.add_row(mark, t.tool_name, str(t.arguments), t.timestamp.strftime("%H:%M:%S"))
        self.console.print(table)

    def sessions_table(self, sessions) -> None:
        from rich.table import Table

        if not sessions:
            self.console.print("No saved sessions.", style="dim")
            return
        table = Table(title="Saved Sessions")
        for col in ("ID", "Name", "Findings", "Hosts", "Saved"):
            table.add_column(col)
        for s in sessions:
            table.add_row(
                str(s["id"]),
                s["name"],
                str(s["findings"]),
                str(s["hosts"]),
                str(s.get("saved_at", "")),
            )
        self.console.print(table)

    def result_panel(self, text: str) -> None:
        from rich.panel import Panel

        self.console.print(Panel(text, title="Result"))

    def info(self, text: str) -> None:
        self.console.print(text)


def get_renderer():
    """Return a RichRenderer if `rich` is importable, else a PlainRenderer."""
    try:
        import rich  # noqa: F401

        return RichRenderer()
    except ImportError:
        return PlainRenderer()
