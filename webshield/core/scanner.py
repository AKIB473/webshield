"""
Scanner orchestrator — runs all modules and collects results.
"""

from __future__ import annotations
import time
import importlib
from typing import List, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .models import ScanResult, Finding
from .http import normalize_url, get_client

console = Console()

# All available module names (order matters — faster checks first)
ALL_MODULES = [
    "ssl_tls",
    "headers",
    "cookies",
    "info_leak",
    "sensitive_paths",
    "cors",
    "csp",
    "dns_email",
    "waf_detect",
    "tech_fingerprint",
    "open_redirect",
    "http_methods",
    "jwt",
    "subdomain_takeover",
    "graphql",
    "request_smuggling",
    "supply_chain",
]

MODULE_LABELS = {
    "ssl_tls":             "SSL/TLS Certificate & Protocols",
    "headers":             "HTTP Security Headers",
    "cookies":             "Cookie Security Flags",
    "info_leak":           "Information Leakage (.env, .git, backups)",
    "sensitive_paths":     "Sensitive Path Exposure",
    "cors":                "CORS Misconfiguration",
    "csp":                 "Content Security Policy",
    "dns_email":           "DNS / SPF / DKIM / DMARC",
    "waf_detect":          "WAF Detection",
    "tech_fingerprint":    "Technology & CVE Fingerprinting",
    "open_redirect":       "Open Redirect",
    "http_methods":        "Dangerous HTTP Methods",
    "jwt":                 "JWT Token Analysis",
    "subdomain_takeover":  "Subdomain Takeover",
    "graphql":             "GraphQL Security",
    "request_smuggling":   "HTTP Request Smuggling",
    "supply_chain":        "Supply Chain / Dependency CVEs",
}


def run_scan(
    target: str,
    modules: Optional[List[str]] = None,
    timeout: float = 10.0,
    verbose: bool = False,
) -> ScanResult:
    """
    Run a full WebShield scan against `target`.
    Returns a populated ScanResult object.
    """
    url = normalize_url(target)
    result = ScanResult(target=url, score=100)
    modules_to_run = modules or ALL_MODULES

    console.print(f"\n[bold cyan]🛡️  WebShield[/bold cyan] scanning [bold]{url}[/bold]\n")

    start = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(modules_to_run))

        for mod_name in modules_to_run:
            label = MODULE_LABELS.get(mod_name, mod_name)
            progress.update(task, description=f"[cyan]Running:[/cyan] {label}")

            try:
                mod = importlib.import_module(f"webshield.modules.{mod_name}")
                findings: List[Finding] = mod.scan(url, timeout=timeout)
                for f in findings:
                    f.module = mod_name
                    result.add_finding(f)
                result.modules_run.append(mod_name)
            except ModuleNotFoundError:
                if verbose:
                    console.print(f"[yellow]  ⚠ Module not found: {mod_name}[/yellow]")
            except Exception as e:
                if verbose:
                    console.print(f"[yellow]  ⚠ {mod_name} error: {e}[/yellow]")

            progress.advance(task)

    result.scan_duration = round(time.time() - start, 2)
    return result
