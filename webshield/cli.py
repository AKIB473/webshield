"""
WebShield CLI — Entry point (v1.5.0)
"""

from __future__ import annotations
import sys
import click
from rich.console import Console

from webshield.core.scanner import run_scan, ALL_MODULES, MODULE_LABELS
from webshield.reporter.terminal import print_result
from webshield.reporter.json_out import save_json, print_json, ci_exit_code
from webshield.reporter.html_report import save_html
from webshield.reporter.sarif import save_sarif

console = Console()


@click.group()
@click.version_option("1.5.0", prog_name="webshield")
def cli():
    """🛡️  WebShield — Website Security Auditor\n
    Know your site's security. Fix it today.\n
    Author: AKIBUZZAMAN AKIB | github.com/AKIB473/webshield
    """
    pass


@cli.command()
@click.argument("target")
@click.option("--modules", "-m", default=None,
              help="Comma-separated list of modules to run (default: all).")
@click.option("--output", "-o", default=None,
              help="Save HTML report (e.g. report.html).")
@click.option("--json", "json_output", default=None,
              help="Save JSON results (e.g. results.json).")
@click.option("--sarif", "sarif_output", default=None,
              help="Save SARIF report for GitHub Code Scanning (e.g. results.sarif).")
@click.option("--print-json", "print_json_flag", is_flag=True, default=False,
              help="Print JSON to stdout instead of terminal report.")
@click.option("--timeout", "-t", default=10.0, show_default=True,
              help="HTTP request timeout in seconds.")
@click.option("--ci", is_flag=True, default=False,
              help="CI mode: exit 1 if findings at or above --fail-on threshold.")
@click.option("--fail-on", default="high", show_default=True,
              type=click.Choice(["critical", "high", "medium", "low"]),
              help="Severity threshold for CI failure.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show module errors and extra detail.")
@click.option("--auth-cookie", "auth_cookies", multiple=True, metavar="NAME=VALUE",
              help="Authenticated cookie (repeat for multiple). e.g. --auth-cookie session=abc123")
@click.option("--auth-header", "auth_headers", multiple=True, metavar="NAME=VALUE",
              help="Auth header (repeat for multiple). e.g. --auth-header 'Authorization=Bearer tok'")
def scan(target, modules, output, json_output, sarif_output,
         print_json_flag, timeout, ci, fail_on, verbose,
         auth_cookies, auth_headers):
    """Scan TARGET for security vulnerabilities.

    \b
    Examples:
      webshield scan https://example.com
      webshield scan https://example.com -o report.html --json results.json
      webshield scan https://example.com --sarif results.sarif
      webshield scan https://example.com --modules ssl_tls,headers,cors
      webshield scan https://example.com --ci --fail-on high
    """
    # Apply auth cookies/headers
    from webshield.core.http import set_auth_cookies, set_auth_headers
    if auth_cookies:
        parsed_cookies = {}
        for c in auth_cookies:
            if "=" in c:
                name, _, val = c.partition("=")
                parsed_cookies[name.strip()] = val.strip()
        if parsed_cookies:
            set_auth_cookies(parsed_cookies)
            console.print(f"[dim]🔑 Auth cookies set: {', '.join(parsed_cookies.keys())}[/dim]")
    if auth_headers:
        parsed_headers = {}
        for h in auth_headers:
            if "=" in h:
                name, _, val = h.partition("=")
                parsed_headers[name.strip()] = val.strip()
        if parsed_headers:
            set_auth_headers(parsed_headers)
            console.print(f"[dim]🔑 Auth headers set: {', '.join(parsed_headers.keys())}[/dim]")

    modules_list = None
    if modules:
        modules_list = [m.strip() for m in modules.split(",")]
        invalid = [m for m in modules_list if m not in ALL_MODULES]
        if invalid:
            console.print(f"[red]Unknown modules: {', '.join(invalid)}[/red]")
            console.print(f"Available: {', '.join(ALL_MODULES)}")
            sys.exit(1)

    result = run_scan(target, modules=modules_list, timeout=timeout, verbose=verbose)

    if print_json_flag:
        print_json(result)
    else:
        print_result(result)

    if json_output:
        save_json(result, json_output)
    if output:
        save_html(result, output)
    if sarif_output:
        save_sarif(result, sarif_output)

    if ci:
        code = ci_exit_code(result, fail_on)
        if code != 0:
            console.print(
                f"[bold red]❌ CI check FAILED — "
                f"{fail_on.upper()}+ severity findings detected.[/bold red]"
            )
        else:
            console.print(
                f"[bold green]✅ CI check PASSED — "
                f"no {fail_on.upper()}+ findings.[/bold green]"
            )
        sys.exit(code)


@cli.command("list-modules")
def list_modules():
    """List all available scan modules."""
    from rich.table import Table
    from rich import box
    table = Table(title="WebShield Modules (v1.5.0)", box=box.ROUNDED, show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Module", style="bold cyan", width=26)
    table.add_column("Description", width=52)
    for i, mod in enumerate(ALL_MODULES, 1):
        label = MODULE_LABELS.get(mod, mod)
        table.add_row(str(i), mod, label)
    console.print(table)
    console.print(f"[dim]Total: {len(ALL_MODULES)} modules[/dim]")


@cli.command()
@click.argument("file1")
@click.argument("file2")
def compare(file1: str, file2: str):
    """Compare two JSON scan results and show what changed.

    \b
    Example:
      webshield compare before.json after.json
    """
    import json
    from pathlib import Path
    from rich.table import Table
    from rich import box

    try:
        r1 = json.loads(Path(file1).read_text())
        r2 = json.loads(Path(file2).read_text())
    except Exception as e:
        console.print(f"[red]Error reading files: {e}[/red]")
        sys.exit(1)

    t1_ids = {f["title"] for f in r1.get("findings", [])}
    t2_ids = {f["title"] for f in r2.get("findings", [])}

    fixed = t1_ids - t2_ids
    new_findings = t2_ids - t1_ids
    remaining = t1_ids & t2_ids

    score1 = r1.get("score", "?")  
    score2 = r2.get("score", "?")
    grade1 = r1.get("grade", "?")
    grade2 = r2.get("grade", "?")

    score_delta = score2 - score1 if isinstance(score1, int) and isinstance(score2, int) else None
    score_color = "green" if (score_delta or 0) > 0 else "red" if (score_delta or 0) < 0 else "white"
    delta_str = f" ([{score_color}]{score_delta:+d}[/{score_color}])" if score_delta is not None else ""

    console.print(f"\n[bold]📊 WebShield Scan Comparison[/bold]")
    console.print(f"  Before: [bold]{file1}[/bold] — Score {score1} ({grade1})")
    console.print(f"  After:  [bold]{file2}[/bold] — Score {score2} ({grade2}){delta_str}\n")

    if fixed:
        console.print(f"[bold green]✅ Fixed ({len(fixed)})[/bold green]")
        for t in sorted(fixed):
            console.print(f"  [green]+ {t}[/green]")

    if new_findings:
        console.print(f"\n[bold red]🆕 New Findings ({len(new_findings)})[/bold red]")
        # Show severity for new findings
        f2_by_title = {f["title"]: f for f in r2.get("findings", [])}
        for t in sorted(new_findings):
            sev = f2_by_title.get(t, {}).get("severity", "?")
            console.print(f"  [red]! [{sev}] {t}[/red]")

    if remaining:
        console.print(f"\n[yellow]⚠ Still Present ({len(remaining)})[/yellow]")
        for t in sorted(remaining):
            console.print(f"  [yellow]- {t}[/yellow]")

    if not fixed and not new_findings:
        console.print("[dim]No changes between scans.[/dim]")
    console.print()


def main():
    cli()


if __name__ == "__main__":
    main()
