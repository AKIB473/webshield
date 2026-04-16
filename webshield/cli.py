"""
WebShield CLI — Entry point (v1.0.1)
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
@click.version_option("1.0.1", prog_name="webshield")
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
def scan(target, modules, output, json_output, sarif_output,
         print_json_flag, timeout, ci, fail_on, verbose):
    """Scan TARGET for security vulnerabilities.

    \b
    Examples:
      webshield scan https://example.com
      webshield scan https://example.com -o report.html --json results.json
      webshield scan https://example.com --sarif results.sarif
      webshield scan https://example.com --modules ssl_tls,headers,cors
      webshield scan https://example.com --ci --fail-on high
    """
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
    table = Table(title="WebShield Modules (v1.0.1)", box=box.ROUNDED, show_lines=True)
    table.add_column("Module", style="bold cyan", width=22)
    table.add_column("Description", width=52)
    for mod in ALL_MODULES:
        label = MODULE_LABELS.get(mod, mod)
        table.add_row(mod, label)
    console.print(table)


def main():
    cli()


if __name__ == "__main__":
    main()
