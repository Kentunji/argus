"""Terminal reporter — rich-styled summary + findings table + triage hints."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.findings import Severity
from src.reporters.base import Reporter
from src.scan_result import ScanResult

_SEVERITY_STYLES = {
    Severity.CRITICAL.value: "bold red",
    Severity.HIGH.value: "red",
    Severity.MEDIUM.value: "yellow",
    Severity.LOW.value: "blue",
    Severity.INFO.value: "dim",
}


class TerminalReporter(Reporter):
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def render(self, result: ScanResult) -> None:
        c = self._console

        header = (
            f"[bold]Target:[/bold]  {result.target}\n"
            f"[bold]Started:[/bold] {result.started_at.isoformat()}\n"
            f"[bold]Duration:[/bold] {result.duration_seconds:.2f}s\n"
            f"[bold]Detectors:[/bold] {', '.join(result.detectors_run) or '(none)'}"
        )
        c.print(Panel(header, title="Argus Scan Summary", border_style="cyan"))

        if result.executive_summary:
            c.print(Panel(
                result.executive_summary,
                title="Executive Summary (AI-generated)",
                border_style="magenta",
            ))

        if not result.findings:
            c.print("\n[green]No findings.[/green]\n")
            return

        table = Table(title=f"\nFindings ({len(result.findings)})", show_lines=True)
        table.add_column("ID", no_wrap=True)
        table.add_column("Severity")
        table.add_column("Type")
        table.add_column("Location", overflow="fold")
        table.add_column("Param", no_wrap=True)
        table.add_column("LLM", no_wrap=True)

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sorted_findings = sorted(
            result.findings,
            key=lambda f: severity_order.index(f.severity.value) if f.severity.value in severity_order else 99,
        )

        for f in sorted_findings:
            sev_style = _SEVERITY_STYLES.get(f.severity.value, "white")
            llm_flag = "—"
            if f.triage:
                if f.triage.is_false_positive:
                    llm_flag = "[dim]FP?[/dim]"
                else:
                    llm_flag = f.triage.confidence.value[:4]
            table.add_row(
                f.id,
                f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                f.type,
                f.evidence.url,
                f.evidence.parameter,
                llm_flag,
            )
        c.print(table)

        counts = result.finding_count_by_severity
        rollup = "  ".join(
            f"[{_SEVERITY_STYLES.get(s, 'white')}]{s}: {counts.get(s, 0)}[/{_SEVERITY_STYLES.get(s, 'white')}]"
            for s in severity_order
            if counts.get(s, 0) > 0
        )
        if rollup:
            c.print(f"\n[bold]Totals:[/bold] {rollup}\n")
