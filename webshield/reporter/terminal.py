"""
Terminal Reporter — Beautiful Rich output with score, grade, tables.
This is one of WebShield's biggest differentiators — nobody else has output this clean.
"""

from __future__ import annotations
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box
from webshield.core.models import ScanResult, Severity

console = Console()

GRADE_COLOR = {
    "A+": "bold bright_green", "A": "bold green",  "A-": "green",
    "B+": "bold cyan",         "B": "cyan",         "B-": "cyan",
    "C+": "bold yellow",       "C": "yellow",       "C-": "yellow",
    "D":  "bold red",          "F": "bold red on white",
}

SCORE_BAR_COLOR = {
    range(90, 101): "bright_green",
    range(75, 90):  "green",
    range(60, 75):  "yellow",
    range(40, 60):  "orange1",
    range(0, 40):   "red",
}


def _score_color(score: int) -> str:
    for rng, color in SCORE_BAR_COLOR.items():
        if score in rng:
            return color
    return "red"


def _score_bar(score: int, width: int = 40) -> str:
    filled = int(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar


def print_result(result: ScanResult) -> None:
    # ── Header ────────────────────────────────────────────────────────
    console.print()
    console.rule("[bold cyan]🛡️  WebShield Security Report[/bold cyan]")
    console.print()

    # ── Score Panel ───────────────────────────────────────────────────
    grade_color  = GRADE_COLOR.get(result.grade, "white")
    score_color  = _score_color(result.score)
    bar          = _score_bar(result.score)

    score_text = Text()
    score_text.append(f"  Target:  ", style="bold")
    score_text.append(f"{result.target}\n")
    score_text.append(f"  Score:   ", style="bold")
    score_text.append(f"{result.score}/100  ", style=f"bold {score_color}")
    score_text.append(f"{bar}\n", style=score_color)
    score_text.append(f"  Grade:   ", style="bold")
    score_text.append(f"  {result.grade}  ", style=f"{grade_color}")
    score_text.append(f"\n  Time:    {result.scan_duration}s  |  "
                      f"Modules: {len(result.modules_run)}  |  "
                      f"Findings: {len(result.findings)}")

    console.print(Panel(score_text, title="[bold]Scan Summary[/bold]",
                        border_style="cyan", padding=(1, 2)))
    console.print()

    # ── Summary counts ────────────────────────────────────────────────
    sev_table = Table(box=box.SIMPLE, show_header=True,
                      header_style="bold", padding=(0, 2))
    sev_table.add_column("Severity",   style="bold", width=12)
    sev_table.add_column("Count",      justify="right", width=8)
    sev_table.add_column("Impact",     width=40)

    impact_map = {
        Severity.CRITICAL: "Active exploitation risk — fix immediately",
        Severity.HIGH:     "Significant attack surface — fix soon",
        Severity.MEDIUM:   "Should be addressed in next release",
        Severity.LOW:      "Minor risk — address when possible",
        Severity.INFO:     "Informational — no action required",
    }

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = len(result.by_severity(sev))
        if count > 0 or sev in (Severity.CRITICAL, Severity.HIGH):
            sev_table.add_row(
                f"{sev.emoji} {sev.value}",
                str(count) if count > 0 else "[dim]0[/dim]",
                impact_map[sev] if count > 0 else "[dim]-[/dim]",
                style=sev.color if count > 0 else "dim",
            )
    console.print(sev_table)
    console.print()

    # ── Findings ──────────────────────────────────────────────────────
    if not result.findings:
        console.print("[bold bright_green]  ✅ No security issues found! Your site looks clean.[/bold bright_green]")
        console.print()
        return

    # Group by severity
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = result.by_severity(sev)
        if not group:
            continue

        console.rule(f"[{sev.color}]{sev.emoji} {sev.value} ({len(group)})[/{sev.color}]")
        console.print()

        for f in group:
            # Finding header
            console.print(f"  [{sev.color}]■[/{sev.color}] [bold]{f.title}[/bold]")
            console.print(f"    [dim]{f.description}[/dim]")

            if f.evidence:
                console.print(f"    [bold]Evidence:[/bold] [yellow]{f.evidence[:200]}[/yellow]")

            if f.remediation:
                console.print(f"    [bold]Fix:[/bold] {f.remediation}")

            if f.code_fix:
                console.print(f"    [bold]Code:[/bold]")
                for line in f.code_fix.split("\n")[:6]:
                    console.print(f"      [bright_black]{line}[/bright_black]")

            if f.reference:
                console.print(f"    [bold]Ref:[/bold] [link={f.reference}]{f.reference}[/link]")

            if f.cvss > 0:
                cvss_color = "red" if f.cvss >= 7.0 else "yellow" if f.cvss >= 4.0 else "green"
                console.print(f"    [bold]CVSS:[/bold] [{cvss_color}]{f.cvss}[/{cvss_color}]")

            console.print()

    # ── Footer ────────────────────────────────────────────────────────
    console.rule()
    console.print(
        f"  [dim]Scanned {result.target} in {result.scan_duration}s  |  "
        f"WebShield v1.0.0  |  "
        "github.com/AKIB473/webshield[/dim]"
    )
    console.print()
